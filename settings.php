<?php
  // these are account wide configuration settings

  // the URL where to the SAML Response/SAML Assertion will be posted
  $const_assertion_consumer_service_url = url('admin/saml/consume'); // "http://localhost/php-saml/consume.php";
  // name of this application
  $const_issuer                         = "onelogin_saml";
  // tells the IdP to return the email address of the current user
  $const_name_identifier_format         = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

  function get_user_settings() {
    // this function should be modified to return the SAML settings for the current user

    $settings                           = new Settings();
    // when using Service Provider Initiated SSO (starting at index.php), this URL asks the IdP to authenticate the user. 
    $settings->idp_sso_target_url       = variable_get('onelogin_saml_login_url', 'PASTE THE SAML LOGIN URL HERE'); //"https://app.onelogin.com/saml/signon/6171";
    // the certificate for the users account in the IdP
    $settings->x509certificate          = variable_get('onelogin_saml_cert', 'PASTE THE SAML CERT FROM ONELOGIN HERE');
    return $settings;
  }
