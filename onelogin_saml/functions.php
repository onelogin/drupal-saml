<?php

function onelogin_saml_sso() {
  $auth = initialize_saml();
  if (isset($_GET['destination'])) {
    $target = $_GET['destination'];
  } else if (isset($_GET['returnTo'])) {
    $target = $_GET['returnTo'];
  }
  if (isset($target) && strpos($target, 'onelogin_saml/sso') === FALSE) {
    $auth->login($target);
  } else {
    $auth->login();
  }
  exit();
}

function onelogin_saml_slo() {
  global $cookie_domain, $user;

  session_destroy();
  $auth = initialize_saml();
  $auth->logout('/');
  exit();
}

function onelogin_saml_acs() {

  if (user_is_logged_in() && !user_is_anonymous()) {
    global $user;
    drupal_set_message("User ". $user->mail ." already logged in.", 'status', FALSE);
    drupal_goto('');
  }
  else if (isset($_POST['SAMLResponse']) && !empty($_POST['SAMLResponse'])){
    $auth = initialize_saml();

    $auth->processResponse();

    $errors = $auth->getErrors();
    if (!empty($errors)) {
      drupal_set_message("There was at least one error processing the SAML Response".implode("<br>", $errors), 'error', FALSE);
      drupal_goto('');
    }
    onelogin_saml_auth($auth);
  }
  else {
    drupal_set_message("No SAML Response found.", 'error', FALSE);
    drupal_goto('');
  }

  if (isset($_POST['RelayState'])) {
    drupal_goto($_POST['RelayState']);
  } else {
    drupal_goto('');
  }
}

function onelogin_saml_sls() {
  $auth = initialize_saml();
  $auth->processSLO();
  $errors = $auth->getErrors();
  if (empty($errors)) {
      session_destroy();
  }
  else {
    $reason = $auth->getLastErrorReason();
    drupal_set_message("SLS endpoint found an error.".$reason, 'error', FALSE);
  }
  
  if (isset($_GET ['destination']) && strpos($_GET ['destination'], 'user/logout') !== FALSE) {
     unset($_GET ['destination']);
  }
  
  drupal_goto('');
}

function onelogin_saml_metadata() {
  $auth = initialize_saml();
  $auth = new Onelogin_Saml2_Auth($settings);
  $settings = $auth->getSettings();
  $metadata = $settings->getSPMetadata();
  header('Content-Type: text/xml');
  echo $metadata;
  exit();
}

function onelogin_saml_auth($auth) {
  $username = '';
  $email = '';

  // Check the NameId. It is required by the SP regardless of the matcher that is chosen.
  $nameId = $auth->getNameId();

  if (empty($nameId)) {
  	drupal_set_message("A NameId could not be found. Please supply a NameId in your SAML response.", 'error', FALSE);
  	drupal_goto();	
  }

  // Get variables from the module configuration.
  $matcher = variable_get('saml_options_account_matcher');
  $autocreate = variable_get('saml_options_autocreate', FALSE);
  $usernameFromEmail = variable_get('saml_options_username_from_email', FALSE);
  $usernameMapping = variable_get('saml_attr_mapping_username');
  $mailMapping = variable_get('saml_attr_mapping_email');
	
  // Get SAML attributes
  $attrs = $auth->getAttributes();

  // If the configuration specifies username as the matcher:
  if ($matcher == 0) {
	$username = $nameId;

    // Setup query for active user given the username.
    $query = new EntityFieldQuery();
    $query->entityCondition('entity_type', 'user')
          ->propertyCondition('status', 1)
          ->propertyCondition('name', $username);

	// If auto-privisioning is enabled but there are no attributes, we need to stop.
	if (empty($attrs) && $autocreate) {
		drupal_set_message("Auto-provisioning accounts requires a username and email address. Please supply both in your SAML response.", 'error', FALSE);
	    drupal_goto();

	// If attributes exist, map them.
	} elseif (!empty($attrs)) {
		if (!empty($mailMapping) && isset($attrs[$mailMapping])  && !empty($attrs[$mailMapping][0])){
	      $email = $attrs[$mailMapping][0];
		}
	}

  // If the configuration specifies email as the matcher:
  } elseif ($matcher == 1) {
	$email = $nameId;

    // Query for active users given an e-mail address.
    $query = new EntityFieldQuery();
    $query->entityCondition('entity_type', 'user')
          ->propertyCondition('status', 1)
          ->propertyCondition('mail', $email);

	// If the username_from_email option is selected, derive the username from the email address.
	if (empty($attrs) && $usernameFromEmail) {
  		$username = str_replace('@', '.', $email);

		// If attributes exist, map them.
	} elseif (!empty($attrs)) {
    	if (!empty($usernameMapping) && isset($attrs[$usernameMapping]) && !empty($attrs[$usernameMapping][0])){
      		$username = $attrs[$usernameMapping][0];
		}
	}
  }

  $syncroles = variable_get('saml_options_syncroles', FALSE);

  $roles = array();
  if ($syncroles) {
    // saml_attr_mapping_role
    $roleMapping = variable_get('saml_attr_mapping_role', '');

    if (!empty($roleMapping) && isset($attrs[$roleMapping]) && !empty($attrs[$roleMapping])) {
      $adminsRole = explode(',', variable_get('saml_role_mapping_administrator', ''));
      // Add here your customRoleMapping directly
      // $customRole = array ('value1', $value2);

      $administrator = user_role_load_by_name('administrator');
      $adminWeight = $administrator->rid;

      $roleWeight = 0;
      foreach ($attrs[$roleMapping] as $samlRole) {
        $samlRole = trim($samlRole);
        if (empty($samlRole)) {
          break;  
        }
    //  else if (in_array($samlRole, $customRole)) {
    //    if ($role < 5) {
    //      $role = 5;
    //    }
    //  }
        else if (in_array($samlRole, $adminsRole)) {
          if ($roleWeight < $adminWeight) {
            $roleWeight = $adminWeight;
          }
          break;
        } else {
          if ($loadedRole = user_role_load_by_name($samlRole)) {
            $roles[$loadedRole->rid] = $loadedRole->name;
          }
        }
      }
      switch ($roleWeight) {
     // case 5:
     //   $roles = array(5 => 'customrole');
     //   break;
        case $adminWeight:
          $roles[$adminWeight] = 'administrator';
          break;
        case DRUPAL_AUTHENTICATED_RID: // default value => 2
        default:
          $roles[DRUPAL_AUTHENTICATED_RID] = 'authenticated user';
          break;
      }
    }
  }

  // If a user exists, attempt to authenticate.
  $result = $query->execute();
  if ($result && $user = user_load(key($result['user']))) {
    $GLOBALS['user'] = $user;
    $form_state['uid'] = $user->uid;

    if (!empty($roles)) {
      try {
        $fields = array(
          'roles' => $roles  
        );          
        user_save($user, $fields);
      }
      catch (Exception $e) {
        return FALSE;
      }
    }
    user_login_finalize($form_state);
	user_cookie_save(array('drupal_saml_login'=>'1'));

  } else if ($autocreate) {
    $fields = array(
      'name' => $username,
      'mail' => $email,
      'pass' => user_password(16),
      'status' => 1,
      'init' => $email,
      'timezone' => date_default_timezone_get()
    );

    if (!empty($roles)) {
      $fields['roles'] = $roles;
    }

    try {
      $user = user_save(NULL, $fields);
      $GLOBALS['user'] = $user;
      $form_state['uid'] = $user->uid;
      user_login_finalize($form_state);
	  user_cookie_save(array('drupal_saml_login'=>'1'));
    }
    catch (Exception $e) {
      return FALSE;
    }
  }
  else {
    drupal_set_message("User '".($matcher == 'username'? $username : $email). "' not found.", 'error', FALSE);
    drupal_goto();
  }
}

function initialize_saml() {
  require_once '_toolkit_loader.php';
  require_once 'settings.php';

  try {
    $auth = new Onelogin_Saml2_Auth($settings);
  } catch (Exception $e) {
    drupal_set_message("The Onelogin SSO/SAML plugin is not correctly configured:".'<br>'.$e->getMessage(), 'error', FALSE);
    drupal_goto();
  }

  return $auth;
}
