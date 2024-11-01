<?php

require_once __DIR__ . '/../vendor/autoload.php';

use FOfX\DropletManager\Manager;
use FOfX\Helper;

$manager   = new Manager('test');
$cyberLink = $manager->connectCyberLink();

$manager->setVerbose(true);

//$domain = 'iffduruguay.org';
//$domain = 'examplesite.com';
//$domain = 'breastsurgeryhawaii.com';
$domain = '022679.xyz';
//$domain = 'australianboatsales.com';

//$ip     = '159.203.109.54';
//$ip = '157.230.89.120';
//$manager->configureDns($domain, $ip);

//print_r($manager->getWebsites());
//print_r($manager->getUsers());
//print_r($manager->getDatabases($domain));
//$manager->verifyConnectionSsh();

//print_r($cyberLink->listUsers());
//print_r($cyberLink->listWebsites());
//print_r($cyberLink->listDatabases($domain));

//$linuxUser = $manager->getLinuxUserForDomain($domain);
//echo $linuxUser . PHP_EOL;

//$manager->createHtaccessForHttpsRedirect($domain);

//echo Helper\sanitize_domain_for_database($domain, 'user123', true, false, 'db_');
//$manager->createDatabase($domain, 'user123', 'password123');
//$manager->dropDatabase($domain, 'user123');
//$manager->grantRemoteDatabaseAccess($domain, 'user123', 'password123');

//print_r($cyberLink->listDatabases($domain));

//$manager->setUserPasswordSsh($domain, 'TCdPvFAR4Q');

//var_dump($manager->enableSymlinksForDomain($domain));

//var_dump($manager->restartLiteSpeed());

//var_dump($manager->updateNameserversNamecheap($domain));

//var_dump($manager->updateNameserversGodaddy($domain, ['ns1.digitalocean.com', 'ns2.digitalocean.com', 'ns3.digitalocean.com']));

//print_r($cyberLink->listUsers());

//var_dump($manager->updateMyCnfPassword());
//var_dump($manager->enableCyberPanelApiAccess());

//var_dump($manager->updateVhostPy());
//var_dump($manager->updateVhostConfsPy());

//var_dump($manager->deleteWebsite($domain, true));
//$manager->setupWebsite($domain, true);

//$manager->setupAliasesAndFunctions();

//var_dump($manager->configureScreen());

//var_dump($manager->updateCyberPanel());

//var_dump($manager->installPhpVersionsAndExtensions(false));

var_dump($manager->configurePhp(true));
