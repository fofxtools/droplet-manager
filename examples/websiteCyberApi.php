<?php

require_once __DIR__ . '/../vendor/autoload.php';

use FOfX\DropletManager\DropletManager;

$dropletManager = new DropletManager('test', 'config' . DIRECTORY_SEPARATOR . 'droplet-manager.config.php');

$data = [
    'firstName'    => 'John',
    'lastName'     => 'Doe',
    'email'        => 'johndoe@email.com',
    'username'     => 'john',
    'password'     => 'password',
    'domainName'   => 'example.com',
    'websiteEmail' => 'admin@example.com',
];

$result = $dropletManager->createWebsiteCyberApi($data);
//$result = $dropletManager->deleteWebsiteCyberApi($data);
var_dump($result);
