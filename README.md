# Droplet Manager

This PHP library provides functionality to manage DigitalOcean droplets, CyberPanel accounts, and DNS settings with GoDaddy and Namecheap.

## Features
- Create and manage DigitalOcean droplets
- Create and delete websites using CyberPanel
- Manage DNS records with GoDaddy and Namecheap

## Installation
1. Clone the repository.
2. Run `composer install` to install dependencies.
3. Copy the configuration example file:
   ```bash
   cp config/droplet-manager.config.php.example config/droplet-manager.config.php
   ```
4. Fill in the necessary API credentials in the configuration file.

## Usage
Here is an example of how to create a droplet:
```php
use FOfX\DropletManager\ConfigurationManager;
use FOfX\DropletManager\DropletManager;

$configManager = new ConfigurationManager();
$dropletManager = new DropletManager($configManager);

$dropletManager->createDroplet('example-droplet', 'nyc3', 's-1vcpu-1gb');
