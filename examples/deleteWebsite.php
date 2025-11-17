<?php

require_once __DIR__ . '/../vendor/autoload.php';

use FOfX\DropletManager\Manager;

// Create a new Manager instance
$manager = new Manager('test');

// Domain name to delete
$domainName = 'examplesite.com';

echo "Deleting website: {$domainName}\n";

// Delete the website (this uses CyberPanel CLI)
$result = $manager->deleteWebsite($domainName);

if ($result) {
    echo "Website deleted successfully.\n";
} else {
    echo "Failed to delete website\n";
}
