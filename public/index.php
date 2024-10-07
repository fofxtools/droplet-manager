<?php

require_once __DIR__ . '/../vendor/autoload.php';

use FOfX\DropletManager\DropletManager;

$dropletManager = new DropletManager('config' . DIRECTORY_SEPARATOR . 'droplet-manager.config.php', 'test');

//print_r($dropletManager->getWebsites());

//var_dump($dropletManager->digitalOceanClient);
//$dropletManager->digitalOceanClient->authenticate($dropletManager->config['digitalocean']['token']);
//var_dump($dropletManager->digitalOceanClient);

$dropletManager->configureDns('iffduruguay.org', '137.184.202.167');
