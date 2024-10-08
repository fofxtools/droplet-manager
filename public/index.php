<?php

require_once __DIR__ . '/../vendor/autoload.php';

use FOfX\DropletManager\DropletManager;

$dropletManager = new DropletManager('test', 'config' . DIRECTORY_SEPARATOR . 'droplet-manager.config.php');

//print_r($dropletManager->getWebsites());
$dropletManager->verifyConnectionSsh();

//$domain = 'iffduruguay.org';
$domain = 'example.com';
$ip     = '137.184.202.167';
//$dropletManager->configureDns($domain, $ip);

//$linuxUser = $dropletManager->getLinuxUserForDomain($domain);
//echo $linuxUser . PHP_EOL;

$dropletManager->createHtaccessForHttpsRedirect($domain);
