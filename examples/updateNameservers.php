<?php

require_once __DIR__ . '/../vendor/autoload.php';

use FOfX\DropletManager\Manager;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Level;

$domain = 'example.com';
// Options: 'namecheap' or 'godaddy'
$registrar = 'namecheap';

// Create a logger
$logger = new Logger('droplet-manager');
$logger->pushHandler(new StreamHandler('php://stdout', Level::Info));

// Create a new Manager instance
$manager = new Manager('test', 'config' . DIRECTORY_SEPARATOR . 'droplet-manager.config.php', null, $logger);

// Update nameservers based on the chosen registrar
if (strtolower($registrar) === 'namecheap') {
    $result = $manager->updateNameserversNamecheap($domain);
    if ($result === false) {
        $logger->error("Failed to update nameservers for {$domain} on Namecheap.");
    } else {
        $logger->info("Successfully updated nameservers for {$domain} on Namecheap.");
        $logger->info('Response from Namecheap API:');
        var_dump($result);
    }
    // @phpstan-ignore-next-line
} elseif (strtolower($registrar) === 'godaddy') {
    $result = $manager->updateNameserversGodaddy($domain);
    if ($result === false) {
        $logger->error("Failed to update nameservers for {$domain} on GoDaddy.");
    } else {
        $logger->info("Successfully updated nameservers for {$domain} on GoDaddy.");
    }
    // @phpstan-ignore-next-line
} else {
    $logger->error("Invalid registrar. Please choose 'namecheap' or 'godaddy'.");
}
