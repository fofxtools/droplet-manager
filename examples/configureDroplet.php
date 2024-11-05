<?php

require_once __DIR__ . '/../vendor/autoload.php';

use FOfX\DropletManager\Manager;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Level;

// Create a logger
$logger = new Logger('droplet-manager');
$logger->pushHandler(new StreamHandler('php://stdout', Level::Info));

// Create a new Manager instance
$manager = new Manager('test', 'config' . DIRECTORY_SEPARATOR . 'droplet-manager.config.php', null, $logger);

// Optionally enable verbose and debug output
//$manager->setVerbose(true);
//$manager->setDebug(true);

// Configure the droplet with custom settings
$logger->info('Starting droplet configuration...');

try {
    $result = $manager->configureDroplet(
        updateCyberPanel: true,   // Update CyberPanel
        updateOs: true,           // Update OS during CyberPanel update
        pipInstall: true,         // pip install
        updateApt: true,          // Update apt packages
        phpDisplayErrors: false,  // PHP display errors
        mysqlPort: 3306,          // MySQL port to open in firewall
        timeout: 3600             // SSH timeout in seconds
    );

    if ($result) {
        $logger->info('Droplet configuration completed successfully!');
    } else {
        $logger->error('Droplet configuration failed.');
    }
} catch (\Exception $e) {
    $logger->error('Error during configuration: ' . $e->getMessage());
}
