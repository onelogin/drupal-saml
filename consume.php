<?php
function onelogin_saml_consume(){
  global $user;
  if ($user->uid){
    drupal_set_message("User ". $user->mail ." already logged in.", 'status', FALSE);
  }
  else if (isset($_POST['SAMLResponse']) && !empty($_POST['SAMLResponse'])){
    require_once dirname(__FILE__) . '/settings.php';
    require_once dirname(__FILE__) . '/lib/onelogin/saml.php';

    $samlresponse = new SamlResponse($_POST['SAMLResponse']);
    $samlresponse->user_settings = get_user_settings();

    if ($samlresponse->is_valid())
      onelogin_saml_auth($samlresponse);
    else
      drupal_set_message("Invalid SAML response.", 'error', FALSE);
    var_dump($samlresponse);
  }
  else
    drupal_set_message("No Saml Response found.", 'error', FALSE);
  drupal_goto('');
}

function onelogin_saml_auth($samlresponse){
  global $user;
  $user = user_load(array('mail' => $samlresponse->get_nameid()));
  if ($user){
    drupal_set_message("Welcome ".$samlresponse->get_nameid(), 'status', FALSE);
    $form_state['uid'] = $user->uid;
    user_login_submit(array(), $form_state);
  }
  else
    drupal_set_message("User '".$samlresponse->get_nameid(). "' not found.", 'error', FALSE);
  drupal_goto('');
}
