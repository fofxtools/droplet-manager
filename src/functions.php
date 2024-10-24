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

/**
 * Sleep for a specified duration in seconds using a float value.
 *
 * This function allows for fractional sleep durations by converting
 * the specified seconds into microseconds and using usleep().
 *
 * @param float $seconds The number of seconds to sleep. Must be non-negative.
 *
 * @throws \InvalidArgumentException if $seconds is negative
 *
 * @return void
 */
function float_sleep(float $seconds): void
{
    if ($seconds < 0) {
        throw new \InvalidArgumentException('The $seconds parameter must be non-negative.');
    }

    $microseconds = (int)ceil($seconds * 1000000);
    usleep($microseconds);
}

/**
 * Sanitize a domain name for use in MySQL database names.
 *
 * @param string $domainName       The domain name to sanitize.
 * @param string $username         An optional username to append to the sanitized domain.
 * @param bool   $includeTLD       Whether to include the TLD in the sanitized domain.
 * @param bool   $forceLetterStart Whether to force the resulting string to start with a letter.
 * @param string $prefix           The prefix to use if forcing the string to start with a letter.
 *
 * @return string The sanitized database name.
 */
function sanitize_domain_for_database(string $domainName, string $username = '', bool $includeTLD = true, bool $forceLetterStart = false, string $prefix = 'db_'): string
{
    // Remove protocol and www prefix, then convert to lowercase
    $domain = strtolower(preg_replace('#^(https?://)?(www\.)?#', '', $domainName));

    if (!$includeTLD) {
        // Remove the TLD
        $domain = preg_replace('/\.[^.]+$/', '', $domain);
    }

    // Replace non-alphanumeric characters with underscores and collapse multiple underscores
    $sanitizedDomain = preg_replace(['/[^a-z0-9]+/', '/_+/'], '_', $domain);

    // Remove leading underscores
    $sanitizedDomain = ltrim($sanitizedDomain, '_');

    // Check if we need to add a prefix
    $needsPrefix = $forceLetterStart && !ctype_alpha($sanitizedDomain[0]);

    // Calculate the maximum domain length
    $maxDomainLength = 64 - (strlen($username) > 0 ? strlen($username) + 1 : 0) - ($needsPrefix ? strlen($prefix) : 0);

    // Truncate the domain if necessary
    $sanitizedDomain = substr($sanitizedDomain, 0, $maxDomainLength);

    // Add prefix if needed
    if ($needsPrefix) {
        $sanitizedDomain = $prefix . $sanitizedDomain;
    }

    // Append username if provided
    if ($username) {
        $sanitizedDomain .= '_' . preg_replace('/[^a-z0-9_]/', '_', strtolower($username));
    }

    // Ensure the final length doesn't exceed 64 characters
    $sanitizedDomain = substr($sanitizedDomain, 0, 64);

    // Remove any trailing underscores from the final result
    return rtrim($sanitizedDomain, '_');
}

/**
 * Generate a password using a random selection of characters.
 *
 * @param int  $length            The length of the password (minimum 4 characters).
 * @param bool $include_numbers   Whether to include numbers in the password.
 * @param bool $include_uppercase Whether to include uppercase letters.
 * @param bool $include_special   Whether to include special characters.
 *
 * @throws \InvalidArgumentException If the password length is less than 4 characters.
 *
 * @return string The generated password.
 */
function generate_password(int $length = 8, bool $include_numbers = true, bool $include_uppercase = true, bool $include_special = false): string
{
    if ($length < 4) {
        throw new \InvalidArgumentException('Password length must be at least 4 characters.');
    }

    // Define character sets
    $char_sets = [
        'lowercase' => 'abcdefghijklmnopqrstuvwxyz',
        'numbers'   => '0123456789',
        'uppercase' => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'special'   => '!@#$%^&*',
    ];

    // Define which character sets to include
    $include_sets = [
        'lowercase' => true,
        'numbers'   => $include_numbers,
        'uppercase' => $include_uppercase,
        'special'   => $include_special,
    ];

    $available_characters = '';
    $password             = '';

    // Build the available characters string and the password string
    foreach ($include_sets as $set => $include) {
        if ($include) {
            $available_characters .= $char_sets[$set];
            $set_length = strlen($char_sets[$set]);
            $password .= $char_sets[$set][random_int(0, $set_length - 1)];
        }
    }

    $available_length = strlen($available_characters);
    // Add characters until the password is the desired length
    while (strlen($password) < $length) {
        $password .= $available_characters[random_int(0, $available_length - 1)];
    }

    // Shuffle the password to ensure randomness
    return str_shuffle($password);
}

/**
 * Escapes a string for use in a shell command executed on Linux.
 *
 * escapeshellarg() works differently when run on Windows. This function attempts to mimic
 * the behavior of Linux's escapeshellarg().
 *
 * @param string $arg The argument to be escaped.
 *
 * @throws \ValueError If the argument contains null bytes.
 *
 * @return string The escaped argument.
 */
function escapeshellarg_linux(string $arg): string
{
    if (strpos($arg, "\0") !== false) {
        throw new \ValueError('Argument must not contain any null bytes');
    }

    // Core Linux shell escaping: wrap in single quotes, escape internal quotes
    return "'" . str_replace("'", "'\\''", $arg) . "'";
}

/**
 * Escapes single quotes for use in sed commands.
 *
 * This function replaces single quotes with the escaped sequence '\''.
 * This is necessary for safely using strings in sed commands.
 *
 * @param string $string The string to escape.
 *
 * @return string The escaped string.
 */
function escape_single_quotes_for_sed(string $string): string
{
    // The backslash is escaped as \\ to represent a literal backslash in the replacement string.
    return str_replace("'", "'\\''", $string);
}
