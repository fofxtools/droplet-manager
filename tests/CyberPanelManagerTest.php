<?php

use FOfX\DropletManager\ConfigurationManager;
use FOfX\DropletManager\CyberPanelManager;
use PHPUnit\Framework\TestCase;

class CyberPanelManagerTest extends TestCase
{
    /**
     * Test that the CyberPanelManager correctly receives the configuration data.
     */
    public function testCyberPanelManagerReceivesConfig()
    {
        $configManager     = new ConfigurationManager();
        $cyberPanelManager = new CyberPanelManager($configManager);

        // You can also mock methods and further test behaviors
        $this->assertInstanceOf(CyberPanelManager::class, $cyberPanelManager);
    }
}
