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

2. Create configuration file:
```bash
cp config/droplet-manager.config.php.example config/droplet-manager.config.php
```

3. Configure your credentials in `droplet-manager.config.php`:
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

## Creating a New Droplet

Follow these steps to create and configure a new droplet:

1. Configure your Digital Ocean API credentials, and set the image ID, in `droplet-manager.config.php`:
```php
return [
    'digitalocean' => [
        'token'    => 'your_do_token',
        'image_id' => 'litespeedtechnol-cyberpanel-20-04',
    ],
    // ... other configurations
];
```

2. Create a new droplet using the provided example script. See `examples/createDroplet.php`:
```php
require_once __DIR__ . '/vendor/autoload.php';

use FOfX\DropletManager\Manager;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Level;

// Create a logger
$logger = new Logger('droplet-manager');
$logger->pushHandler(new StreamHandler('php://stdout', Level::Info));

// Create a new Manager instance
$manager = new Manager(null, 'config/droplet-manager.config.php', null, $logger);

// Set the parameters for the new droplet
$dropletName = 'test-droplet-' . uniqid();
$region      = 'nyc3';
$size        = 's-1vcpu-1gb';

// Create the droplet
$logger->info("Creating droplet '{$dropletName}'...");
$dropletInfo = $manager->createDroplet($dropletName, $region, $size);

$logger->info('var_dump(dropletInfo):');
var_dump($dropletInfo);
```

3. After running the script, wait for an email from Digital Ocean containing:
   - Your droplet's IP address
   - A temporary root password

4. Log into your new droplet. You can use the Digital Ocean droplet console, or SSH (`ssh root@your_droplet_ip`). And set up credentials.
   - You'll be prompted to enter the temporary password
   - You'll then be required to set a new root password
   - You should update the system as prompted

5. Retrieve important passwords from the droplet:
   - CyberPanel admin password: `cat /root/.litespeed_password`
   - MySQL root password: `cat /root/.db_password`

6. Update your configuration file with the new droplet's credentials. The droplet name is `droplet-1` in this example.
```php
return [
    // ... existing config ...
    'droplet-1' => [
        'server_ip'           => 'your_new_droplet_ip',
        'root_password'       => 'your_new_root_password',
        'mysql_root_password' => 'password_from_db_password_file',
        'cyberpanel_port'     => 8090,
        'cyberpanel_admin'    => 'admin',
        'cyberpanel_password' => 'password_from_litespeed_password_file',
    ],
];
```

Your droplet is now ready for use with the Droplet Manager library.

### Configure the Droplet

See `examples/configureDroplet.php`. This method will configure the droplet.

The `configureDroplet()` method performs some server setup:
- System utilities (aliases, screen, nano)
- CyberPanel updates and API configuration
- Install PHP and LiteSpeed PHP versions and extensions
- MySQL remote access configuration and firewall rules
- WP-CLI installation

In the code below, 'test' is the name of the droplet. And the associated section in the config file is `'test' => [ ... ]`.

```php
require_once __DIR__ . '/vendor/autoload.php';

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

$result = $manager->configureDroplet(
    updateCyberPanel: true,
    updateOs: true,
    pipInstall: true,
    updateApt: true,
    phpDisplayErrors: false,
    mysqlPort: 3306
);
var_dump($result);
```

### Create a User

Create a new user.

```php
$result = $manager->connectCyberLink()->createUser(
    firstName: 'John',
    lastName: 'Doe',
    email: 'john.doe@gmail.com',
    username: 'johndoe',
    password: 'secure_password',
    websitesLimit: 0,
    debug: false
);
var_dump($result);
```

### Website Management

See `examples/setupWebsite.php`. This method will create a new website.

```php
// Create a new website
$manager->setupWebsite(
    domainName: 'examplesite.com',
    debug: false,
    websiteEmail: 'john.doe@gmail.com',
    username: 'admin',
    password: 'secure_password'
);
```

### Server Information

```php
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
```

## Requirements

- PHP 8.2 or higher
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

## Credits

Created and maintained by [fofx](https://github.com/fofxtools)