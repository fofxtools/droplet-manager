<?php

use FOfX\DropletManager\ConfigurationManager;
use PHPUnit\Framework\TestCase;

class ConfigurationManagerTest extends TestCase
{
    public function testConfigLoadsCorrectly()
    {
        $configManager = new ConfigurationManager();
        $config        = $configManager->getConfig();

        $this->assertIsArray($config);
        $this->assertArrayHasKey('digitalocean', $config);
        $this->assertArrayHasKey('cyberpanel', $config);
        $this->assertArrayHasKey('namecheap', $config);
        $this->assertArrayHasKey('godaddy', $config);
    }
}
