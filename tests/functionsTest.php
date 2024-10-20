<?php

namespace FOfX\DropletManager\Tests;

use PHPUnit\Framework\TestCase;
use FOfX\DropletManager;

use function FOfX\DropletManager\sanitize_domain_for_database;

class FunctionsTest extends TestCase
{
    public function testSanitizeDomainForDatabaseHandlesSimpleDomain()
    {
        $this->assertEquals('example_com', sanitize_domain_for_database('example.com'));
    }

    public function testSanitizeDomainForDatabasePreservesSubdomain()
    {
        $this->assertEquals('subdomain_example_com', sanitize_domain_for_database('subdomain.example.com'));
    }

    public function testSanitizeDomainForDatabaseRemovesHttpProtocol()
    {
        $this->assertEquals('example_com', sanitize_domain_for_database('http://example.com'));
    }

    public function testSanitizeDomainForDatabaseRemovesHttpsProtocol()
    {
        $this->assertEquals('example_com', sanitize_domain_for_database('https://example.com'));
    }

    public function testSanitizeDomainForDatabaseRemovesWwwPrefix()
    {
        $this->assertEquals('example_com', sanitize_domain_for_database('www.example.com'));
    }

    public function testSanitizeDomainForDatabaseAppendsUsername()
    {
        $this->assertEquals('example_com_user123', sanitize_domain_for_database('example.com', 'user123'));
    }

    public function testSanitizeDomainForDatabaseForcesLetterStart()
    {
        $this->assertEquals('db_123example_com', sanitize_domain_for_database('123example.com', '', true, true));
    }

    public function testSanitizeDomainForDatabaseForcesLetterStartFalse()
    {
        $this->assertEquals('123example_com', sanitize_domain_for_database('123example.com', '', true, false));
    }

    public function testSanitizeDomainForDatabaseAcceptsCustomPrefix()
    {
        $this->assertEquals('custom_123example_com', sanitize_domain_for_database('123example.com', '', true, true, 'custom_'));
    }

    public function testSanitizeDomainForDatabaseTruncatesLongDomain()
    {
        $longDomain = str_repeat('a', 100) . '.com';
        $expected   = str_repeat('a', 64);
        $this->assertEquals($expected, sanitize_domain_for_database($longDomain));
    }

    public function testSanitizeDomainForDatabaseTruncatesLongDomainWithUsername()
    {
        $longDomain = str_repeat('a', 100) . '.com';
        $username   = 'user123';
        $expected   = str_repeat('a', 56) . '_user123'; // 64 chars minus '_user123'
        $this->assertEquals($expected, sanitize_domain_for_database($longDomain, $username));
    }

    public function testSanitizeDomainForDatabaseHandlesSpecialCharacters()
    {
        $this->assertEquals('example_com_special_chars', sanitize_domain_for_database('example.com/special&chars'));
    }

    public function testSanitizeDomainForDatabaseCollapsesMultipleUnderscores()
    {
        $this->assertEquals('multiple_underscores', sanitize_domain_for_database('multiple___underscores'));
    }

    public function testSanitizeDomainForDatabaseHandlesEmptyInput()
    {
        $this->assertEquals('', sanitize_domain_for_database(''));
    }

    public function testSanitizeDomainForDatabaseHandlesUnicodeCharacters()
    {
        $this->assertEquals('example_com', sanitize_domain_for_database('ñ.example.com'));
    }

    public function testSanitizeDomainForDatabaseRemovesTrailingUnderscore()
    {
        $this->assertEquals('example_com', sanitize_domain_for_database('example.com_'));
    }

    public function testSanitizeDomainForDatabaseSanitizesUsernameWithSpecialChars()
    {
        $this->assertEquals('example_com_user_123', sanitize_domain_for_database('example.com', 'user@123'));
    }

    public function testSanitizeDomainForDatabaseWithTLD()
    {
        $this->assertEquals(
            'example_com',
            sanitize_domain_for_database('example.com', '', true, false, 'db_')
        );
    }

    public function testSanitizeDomainForDatabaseWithoutTLD()
    {
        $this->assertEquals(
            'example',
            sanitize_domain_for_database('example.com', '', false, false, 'db_')
        );
    }

    public function testGeneratePasswordDefault()
    {
        $password = DropletManager\generate_password();
        $this->assertEquals(8, strlen($password));
        $this->assertMatchesRegularExpression('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8}$/', $password);
    }

    public function testGeneratePasswordCustomLength()
    {
        $password = DropletManager\generate_password(12);
        $this->assertEquals(12, strlen($password));
    }

    public function testGeneratePasswordWithoutNumbers()
    {
        $password = DropletManager\generate_password(8, false);
        $this->assertMatchesRegularExpression('/^(?=.*[a-z])(?=.*[A-Z])[a-zA-Z]{8}$/', $password);
    }

    public function testGeneratePasswordWithoutUppercase()
    {
        $password = DropletManager\generate_password(8, true, false);
        $this->assertMatchesRegularExpression('/^(?=.*[a-z])(?=.*\d)[a-z\d]{8}$/', $password);
    }

    public function testGeneratePasswordWithSpecialCharacters()
    {
        $password = DropletManager\generate_password(8, true, true, true);
        $this->assertMatchesRegularExpression('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[a-zA-Z\d!@#$%^&*]{8}$/', $password);
    }

    public function testGeneratePasswordMinimumLength()
    {
        $password = DropletManager\generate_password(4);
        $this->assertEquals(4, strlen($password));
    }

    public function testGeneratePasswordInvalidLengthThrowsException()
    {
        $this->expectException(\InvalidArgumentException::class);
        DropletManager\generate_password(3);
    }

    public function testGeneratePasswordLong()
    {
        $length   = 100;
        $password = DropletManager\generate_password($length, true, true, true);
        $this->assertEquals($length, strlen($password));
        $this->assertMatchesRegularExpression('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[a-zA-Z\d!@#$%^&*]{100}$/', $password);
    }

    public function testGeneratePasswordAllCharacterSetsIncluded()
    {
        $password = DropletManager\generate_password(8, true, true, true);
        $this->assertMatchesRegularExpression('/[a-z]/', $password);
        $this->assertMatchesRegularExpression('/[A-Z]/', $password);
        $this->assertMatchesRegularExpression('/\d/', $password);
        $this->assertMatchesRegularExpression('/[!@#$%^&*]/', $password);
    }
}
