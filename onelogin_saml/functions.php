<?php

function onelogin_saml_sso() {

  if (isset($_GET['destination'])) {
    $target = $_GET['destination'];
  } else if (isset($_GET['returnTo'])) {
    $target = $_GET['returnTo'];
  }

  // If a user initiates a login while they are already logged in, simply send them to desired place.
  if (user_is_logged_in() && !user_is_anonymous()) {
    if (isset($target) && strpos($target, 'onelogin_saml/sso') === FALSE) {
      drupal_goto($target);
    } else {
      drupal_goto('');
    }
  }

  $auth = initialize_saml();
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
  global $user;

  if (isset($_POST['RelayState'])) {
    $target = $_POST['RelayState'];
  } else if (isset($_GET['returnTo'])) {
    $target = $_GET['returnTo'];
  } else if (isset($_GET['destination'])) {
    $target = $_GET['destination'];
  }

  // If a user initiates a login while they are already logged in, simply send them to their profile.
  if (user_is_logged_in() && !user_is_anonymous()) {
    if (isset($target) && strpos($target, 'onelogin_saml/sso') === FALSE && strpos($target, 'onelogin_saml/acs') === FALSE) {
      drupal_goto($target);
    } else {
      drupal_goto('');
    }
  }
  else if (isset($_POST['SAMLResponse']) && !empty($_POST['SAMLResponse'])){
    $auth = initialize_saml();

    $auth->processResponse();

    $errors = $auth->getErrors();
    if (!empty($errors)) {
      $settings = $auth->getSettings();
      $debugError = '';
      if ($settings->isDebugActive()) {
        $debugError = "<br>".$auth->getLastErrorReason();
      }
      drupal_set_message("There was at least one error processing the SAML Response<br>".implode("<br>", $errors).$debugError, 'error', FALSE);
    } else {
      onelogin_saml_auth($auth);
    }
  }
  else {
    drupal_set_message("No SAML Response found.", 'error', FALSE);
  }

  if (isset($target) && strpos($target, 'onelogin_saml/sso') === FALSE && strpos($target, 'onelogin_saml/acs') === FALSE) {
    drupal_goto($target);
  } else {
    drupal_goto('');
  }
}

function onelogin_saml_sls() {
  $auth = initialize_saml();
  $auth->processSLO();
  $errors = $auth->getErrors();
  if (empty($errors)) {
      @session_destroy();
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
  $settings = $auth->getSettings();
  $metadata = $settings->getSPMetadata();
  header('Content-Type: text/xml');
  echo $metadata;
  exit();
}

function onelogin_saml_auth($auth) {
  $username = '';
  $email = '';
  $autocreate = variable_get('saml_options_autocreate', FALSE);

  // Get the NameId.
  $nameId = $auth->getNameId();

  if (empty($nameId)) {
    drupal_set_message("A NameId could not be found. Please supply a NameId in your SAML Response.", 'error', FALSE);
    drupal_goto('');
  }

  // Get SAML attributes
  $attrs = $auth->getAttributes();

  $usernameFromEmail = variable_get('saml_options_username_from_email', FALSE);

  if (!empty($attrs)) {
    $usernameMapping = variable_get('saml_attr_mapping_username');
    $mailMapping =  variable_get('saml_attr_mapping_email');

    // Try to get $email and $username from attributes of the SAML Response
    if (!empty($usernameMapping) && isset($attrs[$usernameMapping]) && !empty($attrs[$usernameMapping][0])){
      $username = $attrs[$usernameMapping][0];
    }
    if (!empty($mailMapping) && isset($attrs[$mailMapping])  && !empty($attrs[$mailMapping][0])){
      $email = $attrs[$mailMapping][0];
    }
  }

  // If there are attrs but the mail is in NameID try to obtain it
  if (empty($email) && strpos($nameId, '@')) {
    $email = $nameId;
  }

  if (empty($username) && $usernameFromEmail) {
    $username = str_replace('@', '.', $email);
  }

  $matcher = variable_get('saml_options_account_matcher');
  if ($matcher == 'username') {
    if (empty($username)) {
      drupal_set_message("Username value not found on the SAML Response. Username was selected as the account matcher field. Review at the settings the username mapping and be sure that the IdP provides this value", 'error', FALSE);
      drupal_goto('');
    }
    // Query for active users given an usermail.
    $query = new EntityFieldQuery();
    $query->entityCondition('entity_type', 'user')
          ->propertyCondition('status', 1)
          ->propertyCondition('name', $username);
  }
  else {
    if (empty($email)) {
      drupal_set_message("Email value not found on the SAML Response. Email was selected as the account matcher field. Review at the settings the username mapping and be sure that the IdP provides this value", 'error', FALSE);
      drupal_goto();
    }
    // Query for active users given an e-mail address.
    $query = new EntityFieldQuery();
    $query->entityCondition('entity_type', 'user')
          ->propertyCondition('status', 1)
          ->propertyCondition('mail', $email);
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

    // If auto-privisioning is enabled but there are no required attributes, we need to stop.
    if (empty($email) || empty($username)) {
      drupal_set_message("Auto-provisioning accounts requires a username and email address. Please supply both in your SAML response.", 'error', FALSE);
      drupal_goto();
    }

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
    } else {
      $fields['roles'] = array(DRUPAL_AUTHENTICATED_RID => 'authenticated user');
    }

    try {
      $user = user_save(NULL, $fields);
      $GLOBALS['user'] = $user;
      $form_state['uid'] = $user->uid;
      user_login_finalize($form_state);
      user_cookie_save(array('drupal_saml_login'=>'1'));
      drupal_goto('user/' . $user->uid.'/edit');
    }
    catch (Exception $e) {
      return FALSE;
    }
  }
  else {
    drupal_set_message("User '".($matcher == 'username'? $username : $email). "' not found.", 'error', FALSE);
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
