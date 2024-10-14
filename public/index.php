<?php

require_once __DIR__ . '/../vendor/autoload.php';

use FOfX\DropletManager;
use FOfX\DropletManager\Manager;

$manager   = new Manager('test', 'config' . DIRECTORY_SEPARATOR . 'droplet-manager.config.php');
$cyberLink = $manager->connectCyberLink();

//print_r($manager->getWebsites());
$manager->verifyConnectionSsh();

$dropletName = 'temp-droplet';
$region      = 'nyc3';
$size        = 's-1vcpu-1gb';
$dropletInfo = $manager->createDroplet($dropletName, $region, $size);
var_dump($dropletInfo);

$domain = 'iffduruguay.org';
//$domain = 'example.com';
$ip = '137.184.202.167';
//$manager->configureDns($domain, $ip);

//$linuxUser = $manager->getLinuxUserForDomain($domain);
//echo $linuxUser . PHP_EOL;

//$manager->createHtaccessForHttpsRedirect($domain);

//echo DropletManager\sanitize_domain_for_database($domain, 'user123', true, false, 'db_');
//$manager->createDatabase($domain, 'user123', 'password123');
//$manager->dropDatabase($domain, 'user123');
//$manager->grantRemoteDatabaseAccess($domain, 'user123', 'password123');

//print_r($cyberLink->listDatabases($domain));

//$manager->setUserPasswordSsh($domain, 'TCdPvFAR4Q');

//$manager->enableSymlinksForDomain($domain);

//echo $manager->restartLiteSpeed();

//var_dump($manager->updateNameserversNamecheap($domain));
