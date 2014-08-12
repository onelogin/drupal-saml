<?php

$settings = array (

  'strict' => variable_get('saml_advanced_settings_strict_mode', false),
  'debug' => variable_get('saml_advanced_settings_debug', false),

  'sp' => array (
    'entityId' => variable_get('saml_advanced_settings_sp_entity_id', 'php-saml'),
    'assertionConsumerService' => array (
      'url' => url('onelogin_saml/acs', array('absolute' => true)),
    ),
    'singleLogoutService' => array (
      'url' => url('onelogin_saml/sls', array('absolute' => true)),
    ),
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'x509cert' => variable_get('saml_advanced_settings_sp_x509cert', ''),
    'privateKey' => variable_get('saml_advanced_settings_sp_privatekey', ''),
  ),

  'idp' => array (
    'entityId' => variable_get('saml_idp_entityid', ''),
    'singleSignOnService' => array (
      'url' => variable_get('saml_idp_sso', ''),
    ),
    'singleLogoutService' => array (
      'url' => variable_get('saml_idp_slo', ''),
    ),
    'x509cert' => variable_get('saml_idp_x509cert', ''),
  ),

  'security' => array (
    'signMetadata' => false,
    'nameIdEncrypted' => variable_get('saml_advanced_settings_nameid_encrypted', false),
    'authnRequestsSigned' => variable_get('saml_advanced_settings_authn_request_signed', false),
    'logoutRequestSigned' => variable_get('saml_advanced_settings_logout_request_signed', false),
    'logoutResponseSigned' => variable_get('saml_advanced_settings_logout_response_signed', false),
    'wantMessagesSigned' => variable_get('advanced_settings_want_message_signed', false),
    'wantAssertionsSigned' => variable_get('saml_advanced_settings_want_assertion_signed', false),
    'wantAssertionsEncrypted' => variable_get('saml_advanced_settings_want_assertion_encrypted', false),
  )
);
