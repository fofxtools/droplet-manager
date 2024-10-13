<?php

require_once __DIR__ . '/../vendor/autoload.php';

use FOfX\DropletManager\Manager;

$manager = new Manager('test', 'config' . DIRECTORY_SEPARATOR . 'droplet-manager.config.php');

$data = [
    'firstName'    => 'John',
    'lastName'     => 'Doe',
    'email'        => 'johndoe@email.com',
    'username'     => 'john',
    'password'     => 'password',
    'domainName'   => 'example.com',
    'websiteEmail' => 'admin@example.com',
];

$result = $manager->createWebsiteCyberApi($data);
//$result = $manager->deleteWebsiteCyberApi($data);
var_dump($result);
