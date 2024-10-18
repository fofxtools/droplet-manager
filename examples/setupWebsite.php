<?php

require_once __DIR__ . '/../vendor/autoload.php';

use FOfX\DropletManager\Manager;
use FOfX\DropletManager\CyberLink;

// Create a new Manager instance
$manager = new Manager('test2');

// Data for setting up a website
$websiteData = [
    'firstName'     => 'John',
    'lastName'      => 'Doe',
    'email'         => 'john.doe@gmail.com',
    'username'      => 'johndoe',
    'password'      => 'Qc!ftl2gJ7u',
    'websitesLimit' => 0,
    'domainName'    => 'example.com',
    'websiteEmail'  => 'john.doe@gmail.com',
];

// Call the setupWebsite method
try {
    //$manager->setupWebsite($websiteData);
    //echo "Website setup completed successfully!\n";
    $cyberLink = $manager->connectCyberLink();
    //$user = $cyberLink->createUser($websiteData['firstName'], $websiteData['lastName'], $websiteData['email'], $websiteData['username'], $websiteData['password'], $websiteData['websitesLimit']);
    //var_dump($user);
    $result = $cyberLink->createWebsite($websiteData['domainName'], $websiteData['websiteEmail'], $websiteData['username'] ?? CyberLink::owner, CyberLink::package, CyberLink::phpVersion, true);
    var_dump($result);
} catch (\Exception $e) {
    echo 'An error occurred during website setup: ' . $e->getMessage() . "\n";
}
