<?php
    error_reporting(E_ALL);

    require '_toolkit_loader.php';
    require 'settings.php';

try {
    $auth = new Onelogin_Saml2_Auth($settings);
    $auth->login();
} catch (Exception $e) {
    drupal_set_message("The Onelogin SSO/SAML plugin is not correctly configured.", 'error', FALSE);
    exit();
}
