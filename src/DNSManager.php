<?php

namespace FOfX\DropletManager;

class DNSManager
{
    private $config;

    public function __construct(ConfigurationManager $configManager)
    {
        // Retrieve the config array from the ConfigurationManager
        $this->config = $configManager->getConfig();
    }

    public function setDNSNamecheap($domain, $ip)
    {
        // Example usage of $this->config for Namecheap API
        $username = $this->config['namecheap']['username'];
        $token    = $this->config['namecheap']['token'];
        // Proceed with setting DNS using Namecheap API and these config values
    }

    public function setDNSGodaddy($domain, $ip)
    {
        // Example usage of $this->config for GoDaddy API
        $apiKey    = $this->config['godaddy']['api_key'];
        $apiSecret = $this->config['godaddy']['api_secret'];
        // Proceed with setting DNS using GoDaddy API and these config values
    }
}
