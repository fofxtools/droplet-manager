<?php

require_once __DIR__ . '/../vendor/autoload.php';

use FOfX\DropletManager\DropletManager;

$dropletManager = new DropletManager('config' . DIRECTORY_SEPARATOR . 'droplet-manager.config.php', 'test');

//print_r($dropletManager->getWebsites());

$domain = 'iffduruguay.org';
$ip = '137.184.202.167';
$dropletManager->configureDns($domain, $ip);
