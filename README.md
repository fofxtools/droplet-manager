# Droplet Manager

This PHP library provides functionality to manage DigitalOcean droplets, CyberPanel accounts, and DNS settings with GoDaddy and Namecheap. This library provides a set of tools for automating server management tasks, and website deployments.

## Features

- **DigitalOcean Management**
  - Create and configure droplets
  - Manage DNS records

- **CyberPanel Integration**
  - Create and manage websites
  - Configure PHP versions and extensions
  - Manage databases
  - Handle user accounts

- **DNS Management**
  - Support for Namecheap and GoDaddy
  - Automated DNS record configuration
  - Nameserver updates

- **Server Configuration**
  - Automated HTTPS setup
  - PHP version management
  - MySQL configuration
  - Security settings

## Installation

1. Install via Composer:
```bash
composer require fofx/droplet-manager
```

2. Create config folder and configuration file:
```bash
mkdir -p config && cp vendor/fofx/droplet-manager/config/droplet-manager.config.php.example config/droplet-manager.config.php
```

3. Configure your credentials in `config/droplet-manager.config.php`:
```php
return [
    'digitalocean' => [
        'token'    => 'your_do_token',
        'image_id' => 'litespeedtechnol-cyberpanel-20-04',
    ],
    'namecheap' => [
        'username' => 'your_username',
        'token'    => 'your_token',
    ],
    'godaddy' => [
        'api_key'    => 'your_godaddy_key',
        'api_secret' => 'your_godaddy_secret',
    ],
    // ... other configurations
];
```

## Usage

See [docs/usage.md](docs/usage.md) for more detailed usage instructions.

## Setup

- Install: `composer require fofx/droplet-manager`
- Copy config: `cp vendor/fofx/droplet-manager/config/droplet-manager.config.php.example config/droplet-manager.config.php`
- Add your DigitalOcean API token to `config/droplet-manager.config.php`

## Workflow

- **Create droplet** → `$manager->createDroplet($dropletName, $region, $size)`
- **Wait for email** → DigitalOcean emails you the root password
- **Get credentials** → Log in to the droplet, run `cat /root/.litespeed_password` and `cat /root/.db_password`
- **Add to config** → Update config file with droplet IP and passwords
- **Configure server** → `$manager->configureDroplet()` (installs PHP, MySQL, tools)
- **Create website** → `$manager->setupWebsite(domainName: 'example.com', websiteEmail: 'admin@example.com', phpVersion: '8.4')`

## Requirements

- PHP 8.1 or higher
- Composer
- Required PHP extensions:
  - curl
  - json
  - xml
  - mbstring

## Developer Tools

Run the PHPUnit test suite:

```bash
composer test
```

Run PHPStan static analysis:

```bash
composer analyse
```

Run PHP-CS-Fixer:

```bash
composer cs-fix
```

## License

This project is licensed under the MIT License.