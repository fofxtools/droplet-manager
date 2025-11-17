<?php

require_once __DIR__ . '/../vendor/autoload.php';

use FOfX\DropletManager\Manager;

$startTime = microtime(true);

// Create a new Manager instance
$manager = new Manager('test');

// List websites
$websites = $manager->getWebsites();
echo "Websites:\n";
print_r($websites);

// List users
$users = $manager->getUsers();
echo "Users:\n";
print_r($users);

// List databases for each website
foreach ($websites as $website) {
    echo "Databases for {$website}:\n";
    $databases = $manager->getDatabases($website);
    print_r($databases);
}

$end      = microtime(true);
$duration = $end - $startTime;
echo "Duration: {$duration} seconds.\n";
