<?php

namespace FOfX\DropletManager;

/**
 * DNSManager class
 *
 * This class is responsible for managing DNS records for domains using Namecheap
 * and GoDaddy APIs, with configurations provided by the ConfigurationManager.
 */
class DNSManager
{
    private $config;

    /**
     * Constructor: Retrieve the configuration for DNS management.
     *
     * @param ConfigurationManager $configManager the configuration manager instance
     */
    public function __construct(ConfigurationManager $configManager)
    {
        // Retrieve the config array from the ConfigurationManager
        $this->config = $configManager->getConfig();
    }

    /**
     * Set DNS records for a domain using Namecheap API.
     *
     * @param string $domain the domain name
     * @param string $ip     the IP address to set for the domain
     *
     * @return void
     */
    public function setDNSNamecheap($domain, $ip)
    {
        // Example usage of $this->config for Namecheap API
        $username = $this->config['namecheap']['username'];
        $token    = $this->config['namecheap']['token'];
        // Proceed with setting DNS using Namecheap API and these config values
    }

    /**
     * Set DNS records for a domain using GoDaddy API.
     *
     * @param string $domain the domain name
     * @param string $ip     the IP address to set for the domain
     *
     * @return void
     */
    public function setDNSGodaddy($domain, $ip)
    {
        // Example usage of $this->config for GoDaddy API
        $apiKey    = $this->config['godaddy']['api_key'];
        $apiSecret = $this->config['godaddy']['api_secret'];
        // Proceed with setting DNS using GoDaddy API and these config values
    }
}
