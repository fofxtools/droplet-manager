<?php

require_once __DIR__ . '/../vendor/autoload.php';

use FOfX\DropletManager\Manager;

$manager = new Manager('test');

// List websites
$websites = $manager->getWebsites();
print_r($websites);

// List users
$users = $manager->getUsers();
print_r($users);

// List databases for each website
foreach ($websites as $website) {
    $databases = $manager->getDatabases($website);
    print_r($databases);
}
