<?php

function onelogin_saml_sso() {
  $auth = initialize_saml();
  if (isset($_SERVER['REQUEST_URI'])) {
    $auth->login($_SERVER['REQUEST_URI']);
  } else {
    $auth->login();
  }
  exit();
}

function onelogin_saml_slo() {
  global $cookie_domain, $user;

  setcookie('drupal_saml_login', 0, time() + 360000);
  $auth = initialize_saml();
  //$auth->logout(url('user/logout', array('absolute' => FALSE)));
  $auth->logout(url('', array('relative' => TRUE)));
  exit();
}

function onelogin_saml_acs() {

  if (drupal_session_started()){
    global $user;
    drupal_set_message("User ". $user->mail ." already logged in.", 'status', FALSE);
  }
  else if (isset($_POST['SAMLResponse']) && !empty($_POST['SAMLResponse'])){
    $auth = initialize_saml();

    $auth->processResponse();

    $errors = $auth->getErrors();
    if (!empty($errors)) {
      drupal_set_message("There was at least one error processing the SAML Response".implode("<br>", $errors), 'error', FALSE);
    }
    onelogin_saml_auth($auth);
  }
  else {
    drupal_set_message("No SAML Response found.", 'error', FALSE);
  }
  drupal_goto('');
}

function onelogin_saml_sls() {
  $auth = initialize_saml();
  $auth->processSLO();  
  drupal_goto();
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
  $attrs = $auth->getAttributes();

  if (empty($attrs)) {
    $email = $auth->getNameId();
    $username = str_replace('@', '.', $email);
  } else {
    $usernameMapping = variable_get('saml_attr_mapping_username');
    $mailMapping =  variable_get('saml_attr_mapping_email');

    if (!empty($usernameMapping) && isset($attrs[$usernameMapping]) && !empty($attrs[$usernameMapping][0])){
      $username = $attrs[$usernameMapping][0];
    }
    if (!empty($mailMapping) && isset($attrs[$mailMapping])  && !empty($attrs[$mailMapping][0])){
      $email = $attrs[$mailMapping][0];
    }
  }

  $matcher = variable_get('saml_options_account_matcher');
  if ($matcher == 'username') {
    // Query for active users given an usermail.
    $query = new EntityFieldQuery();
    $query->entityCondition('entity_type', 'user')
          ->propertyCondition('status', 1)
          ->propertyCondition('usermail', $usermail);
  }
  else {
    // Query for active users given an e-mail address.
    $query = new EntityFieldQuery();
    $query->entityCondition('entity_type', 'user')
          ->propertyCondition('status', 1)
          ->propertyCondition('mail', $email);
  }

  $autocreate = variable_get('saml_options_autocreate', FALSE);
  $syncrole = variable_get('saml_options_syncrole', FALSE);

  $roles = array();
  if ($syncrole) {
    // saml_attr_mapping_role
    $roleMapping = variable_get('saml_attr_mapping_role', '');

    if (!empty($roleMapping)) {
      $adminsRole = explode(',', variable_get('saml_role_mapping_administrator', ''));
      $authRole = explode(',', variable_get('saml_role_mapping_authenticated'));
      // Add here your customRoleMapping directly
      // $customRole = array ('value1', $value2);

      $role = 0;
      foreach ($attrs[$roleMapping] as $samlRole) {
        $samlRole = trim($samlRole);
        if (empty($samlRole)) {
          break;  
        }
        else if (in_array($samlRole, $adminsRole)) {
          if ($role < 10) {
            $role = 10;
          }
          break;
    // } else if (in_array($samlRole, $customRole)) {
    //    if ($role < 5) {
    //      $role = 5;
    //    }
        } else if (in_array($samlRole, $authRole)) {
          if ($role < 1) {
            $role = 1;
          }
          break;
        }
      }
      switch ($role) {
        case 10:
          $roles = array(3 => 'administrator');
          break;
        case 1:
          $roles = array(DRUPAL_AUTHENTICATED_RID => 'authenticated user');
          break;
     // case 5:
     //   $roles = array(5 => 'customrole');
     //   break;
        default:
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
    setcookie('drupal_saml_login', 1, time() + 360000);

  } else if ($autocreate) {
    $fields = array(
      'name' => $username,
      'mail' => $email,
      'pass' => user_password(16),
      'status' => 1,
      'init' => $email,
    );

    if (!empty($roles)) {
      $fields['roles'] = $roles;
    }

    try {
      setcookie('drupal_saml_login', 1, time() + 360000);
      return user_save(NULL, $fields);
    }
    catch (Exception $e) {
      return FALSE;
    }
  }
  else {
    drupal_set_message("User '".($matcher == 'username'? $username : $email). "' not found.", 'error', FALSE);
  }
  drupal_goto();
}

function initialize_saml() {
  $module_path = DRUPAL_ROOT . '/' . drupal_get_path('module', 'onelogin_saml') . '/';
  require_once $module_path.'_toolkit_loader.php';
  require_once $module_path.'settings.php';

  try {
    $auth = new Onelogin_Saml2_Auth($settings);
  } catch (Exception $e) {
    drupal_set_message("The Onelogin SSO/SAML plugin is not correctly configured:".'<br>'.$e->getMessage(), 'error', FALSE);
    drupal_goto();    
  }

  return $auth;
}
