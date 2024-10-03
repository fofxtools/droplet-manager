<?php

/**
 * Core Utility Functions for Droplet Manager
 *
 * This file contains core utility functions used throughout the Droplet Manager library.
 * It includes functions for configuration management, environment detection,
 * and other general-purpose utilities.
 *
 * Key features:
 * - Configuration file resolution and loading
 * - PHPUnit environment detection
 */

namespace FOfX\DropletManager;

/**
 * Resolves the file path to the configuration file.
 *
 * This function searches for the configuration file in multiple locations:
 * 1. In the vendor directory (if the package is installed via Composer)
 * 2. In the current working directory
 * 3. In the parent directory of the current working directory
 *
 * @param string|null $config_file The name or relative path of the configuration file.
 *
 * @return string|null The resolved absolute path to the configuration file, or null if not found.
 */
function resolve_config_file_path(?string $config_file = 'config' . DIRECTORY_SEPARATOR . 'droplet-manager.config.php'): ?string
{
    if ($config_file === null) {
        return null;
    }

    // Check if the package is installed via Composer
    $vendorPath = dirname(__DIR__, 3);
    $configPath = dirname(__DIR__, 4) . DIRECTORY_SEPARATOR . $config_file;
    if (basename($vendorPath) === 'vendor' && is_readable($configPath)) {
        // Return the config path, not the vendor path
        return $configPath;
    }

    // Check in current and parent working directories
    $possiblePaths = [
        getcwd() . DIRECTORY_SEPARATOR . $config_file,
        dirname(getcwd()) . DIRECTORY_SEPARATOR . $config_file,
    ];

    foreach ($possiblePaths as $path) {
        if (is_readable($path)) {
            return $path;
        }
    }

    // Config file not found
    return null;
}

/**
 * Loads the configuration from a specified file.
 *
 * @param string $config_file The path to the configuration file.
 *
 * @throws \RuntimeException If the configuration file is not found or invalid.
 *
 * @return array The configuration data loaded from the file.
 */
function load_config(string $config_file = 'config' . DIRECTORY_SEPARATOR . 'droplet-manager.config.php'): array
{
    if (!file_exists($config_file)) {
        throw new \RuntimeException("Configuration file not found: $config_file");
    }

    $config = include $config_file;

    if (!is_array($config)) {
        throw new \RuntimeException("Invalid configuration format in file: $config_file");
    }

    return $config;
}

/**
 * Check if the script is in a PHPUnit testing environment.
 *
 * @param bool $include_class_check Whether to include the PHPUnit TestCase class check.
 * @param bool $skip_constant_check Whether to ignore PHPUnit-specific constants (for testing purposes).
 *
 * @return bool True if in a PHPUnit environment, false otherwise.
 */
function is_phpunit_environment(bool $include_class_check = false, bool $skip_constant_check = false): bool
{
    // Check if the PHPUNIT_COMPOSER_INSTALL or PHPUnit's standard test suite constant is defined.
    if (!$skip_constant_check && (defined('PHPUNIT_COMPOSER_INSTALL') || defined('__PHPUNIT_BOOTSTRAP'))) {
        return true;
    }

    // Check for the existence of an environment variable that is set by PHPUnit
    if (getenv('PHPUNIT_TEST') !== false) {
        return true;
    }

    // Optionally check for the existence of the PHPUnit TestCase class
    if ($include_class_check && class_exists('\PHPUnit\Framework\TestCase', false)) {
        return true;
    }

    return false;
}
