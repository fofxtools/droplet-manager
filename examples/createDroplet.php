<?php

require_once __DIR__ . '/../vendor/autoload.php';

use FOfX\DropletManager\Manager;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Level;

// Create a logger
$logger = new Logger('droplet_creation');
$logger->pushHandler(new StreamHandler('php://stdout', Level::Info));

// Create a new Manager instance
$manager = new Manager(null, 'config' . DIRECTORY_SEPARATOR . 'droplet-manager.config.php', null, $logger);

// Set the parameters for the new droplet
$dropletName = 'test-droplet-' . uniqid();
$region      = 'nyc3';
$size        = 's-1vcpu-1gb';

// Create the droplet
$logger->info("Creating droplet '{$dropletName}'...");
$dropletInfo = $manager->createDroplet($dropletName, $region, $size);

// Check if droplet creation was successful
if ($dropletInfo !== null) {
    $logger->info('Droplet created successfully!');
    $logger->info('Droplet details:', [
        'ID'         => $dropletInfo['id'],
        'Name'       => $dropletInfo['name'],
        'Status'     => $dropletInfo['status'],
        'IP Address' => $dropletInfo['networks'][0]['ipAddress'],
        'Region'     => $dropletInfo['region'],
        'Size'       => $dropletInfo['size'],
    ]);
} else {
    $logger->error('Failed to create droplet.');
}

$logger->info('var_dump(dropletInfo):');
var_dump($dropletInfo);
