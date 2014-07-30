<?php
function onelogin_saml_consume(){
  if (drupal_session_started()){
    global $user;
    drupal_set_message("User ". $user->mail ." already logged in.", 'status', FALSE);
  }
  else if (isset($_POST['SAMLResponse']) && !empty($_POST['SAMLResponse'])){
    $module_path = DRUPAL_ROOT . '/' . drupal_get_path('module', 'onelogin_saml') . '/';
    require_once $module_path.'settings.php';
    require_once $module_path.'lib/onelogin/saml.php'

    $samlresponse = new SamlResponse($_POST['SAMLResponse']);
    $samlresponse->user_settings = get_user_settings();

    if ($samlresponse->is_valid())
      onelogin_saml_auth($samlresponse);
    else
      drupal_set_message("Invalid SAML response.", 'error', FALSE);
  }
  else
    drupal_set_message("No Saml Response found.", 'error', FALSE);
  drupal_goto('');
}

function onelogin_saml_auth($samlresponse){
  $user = db_query("SELECT * FROM {users} WHERE mail = :email AND status = 1", array(':email' => $samlresponse->get_nameid()))->fetchObject();
  if ($user){
    drupal_set_message("Welcome ".$samlresponse->get_nameid(), 'status', FALSE);
    $form_state['uid'] = $user->uid;
    user_login_submit(array(), $form_state);
  }
  else
    drupal_set_message("User '".$samlresponse->get_nameid(). "' not found.", 'error', FALSE);
  drupal_goto('');
}
