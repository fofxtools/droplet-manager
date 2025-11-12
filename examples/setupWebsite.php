<?php

require_once __DIR__ . '/../vendor/autoload.php';

use FOfX\DropletManager\Manager;

// Create a new Manager instance
$manager = new Manager('test');

// Data for setting up a website
$domainName   = 'examplesite.com';
$websiteEmail = 'admin@' . $domainName;
$firstName    = 'John';
$lastName     = 'Doe';
$userEmail    = $websiteEmail;

// Auto-generate username from domain
$username = substr(preg_replace('/[^a-z0-9]/', '', strtolower($domainName)), 0, 16);

$password      = 'Qc!ftl2gJ7u';
$websitesLimit = 0;

// Call the setupWebsite method
try {
    $debug = true;
    $manager->setupWebsite($domainName, $debug, $websiteEmail, $firstName, $lastName, $userEmail, $username, $password, $websitesLimit);
    echo "Website setup completed successfully!\n";
} catch (\Exception $e) {
    echo 'An error occurred during website setup: ' . $e->getMessage() . "\n";
}
