<?php

require_once __DIR__ . '/../vendor/autoload.php';

use FOfX\DropletManager\DropletManager;

$dropletManager = new DropletManager('test', 'config' . DIRECTORY_SEPARATOR . 'droplet-manager.config.php');

$data = [
    'firstName' => 'John',
    'lastName' => 'Doe',
    'email' => 'johndoe@email.com',
    'username' => 'john',
    'password' => 'password',
    'domainName' => 'example3.com',
    'websiteEmail' => 'admin@example3.com'
];

$result = $dropletManager->createWebsiteCyberApi($data);
var_dump($result);
