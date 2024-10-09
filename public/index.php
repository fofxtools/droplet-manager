<?php

require_once __DIR__ . '/../vendor/autoload.php';

use FOfX\DropletManager\DropletManager as DropletManagerClass;
use FOfX\DropletManager as DropletManager;

$dropletManager = new DropletManagerClass('test', 'config' . DIRECTORY_SEPARATOR . 'droplet-manager.config.php');
$cyberLink      = $dropletManager->connectCyberLink();

//print_r($dropletManager->getWebsites());
$dropletManager->verifyConnectionSsh();

//$domain = 'iffduruguay.org';
$domain = 'example.com';
$ip     = '137.184.202.167';
//$dropletManager->configureDns($domain, $ip);

//$linuxUser = $dropletManager->getLinuxUserForDomain($domain);
//echo $linuxUser . PHP_EOL;

//$dropletManager->createHtaccessForHttpsRedirect($domain);

//echo DropletManager\sanitize_domain_for_database($domain, 'user123', false, 'db_', false);
//$dropletManager->createDatabase($domain, 'user123', 'password123');
//$dropletManager->dropDatabase($domain, 'user123');
//$dropletManager->grantRemoteDatabaseAccess($domain, 'user123', 'password123');

//print_r($cyberLink->listDatabases($domain));

//$dropletManager->setUserPasswordSsh($domain, 'TCdPvFAR4Q');

//$dropletManager->enableSymlinksForDomain($domain);

//echo $dropletManager->restartLiteSpeed();
