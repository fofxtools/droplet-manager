<?php

namespace FOfX\DropletManager\Tests;

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
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

    public static function escapeshellargLinuxProvider()
    {
        return [
            'Basic string'                   => ['hello', "'hello'"],
            'String with single quotes'      => ["It's a test", "'It'\\''s a test'"],
            'String with special characters' => ['!@#$%^&*()_+', "'!@#$%^&*()_+'"],
            'String with spaces'             => ['Hello World', "'Hello World'"],
            'String with newlines'           => ["Hello\nWorld", "'Hello\nWorld'"],
            'String with tabs'               => ["Hello\tWorld", "'Hello\tWorld'"],
            'String with control characters' => ["Hello\x01World", "'Hello\x01World'"],
            'Empty string'                   => ['', "''"],
            'Non-string input'               => [123, "'123'"],
        ];
    }

    #[DataProvider('escapeshellargLinuxProvider')]
    public function testEscapeshellargLinux($input, $expected)
    {
        $this->assertEquals($expected, DropletManager\escapeshellarg_linux($input));
    }

    public function testEscapeshellargLinuxWithNullByteThrowsException()
    {
        $this->expectException(\ValueError::class);
        DropletManager\escapeshellarg_linux("Hello\0World");
    }

    /**
     * Data provider for Unix-like escapeshellcmd_os tests
     */
    public static function escapeshellcmdOsUnixProvider(): array
    {
        return [
            'Empty string'           => ['', ''],
            'Simple command'         => ['ls -la', 'ls -la'],
            'Command with &'         => ['echo Hello & World', 'echo Hello \\& World'],
            'Single quotes'          => ['echo \'Hello World\'', 'echo \'Hello World\''],
            'Unmatched single quote' => ['echo \'Unmatched quote', 'echo \\\'Unmatched quote'],
            'Double quotes'          => ['echo "Hello World"', 'echo "Hello World"'],
            'Unmatched double quote' => ['echo "Unmatched quote', 'echo \\"Unmatched quote'],
            'Backticks'              => ['ls `uname -a`', 'ls \\`uname -a\\`'],
            'Dollar sign'            => ['echo $HOME', 'echo \\$HOME'],
            'Backslash'              => ['echo \\$', 'echo \\\\\\$'],
            'Semicolon'              => ['echo Dangerous; rm -rf /', 'echo Dangerous\\; rm -rf /'],
            'Newline'                => ["echo Hello\nWorld", "echo Hello\\\nWorld"],
            'Multiple special chars' => ['echo \'Single\' "Double"', 'echo \'Single\' "Double"'],
            'Multiple commands'      => ['echo \'Single\' & echo "Double"', 'echo \'Single\' \\& echo "Double"'],
            'Special characters'     => ['echo !@#$%^&*()[]{}', 'echo !@\\#\\$%\\^\\&\\*\\(\\)\\[\\]\\{\\}'],
            'Non-ASCII characters'   => ["echo \xFF", 'echo '],
        ];
    }

    /**
     * Data provider for Windows escapeshellcmd_os tests
     */
    public static function escapeshellcmdOsWindowsProvider(): array
    {
        return [
            'Empty string'           => ['', ''],
            'Simple command'         => ['ls -la', 'ls -la'],
            'Command with &'         => ['echo Hello & World', 'echo Hello ^& World'],
            'Single quotes'          => ['echo \'Hello World\'', 'echo ^\'Hello World^\''],
            'Unmatched single quote' => ['echo \'Unmatched quote', 'echo ^\'Unmatched quote'],
            'Double quotes'          => ['echo "Hello World"', 'echo ^"Hello World^"'],
            'Unmatched double quote' => ['echo "Unmatched quote', 'echo ^"Unmatched quote'],
            'Backticks'              => ['ls `uname -a`', 'ls ^`uname -a^`'],
            'Dollar sign'            => ['echo $HOME', 'echo ^$HOME'],
            'Backslash'              => ['echo \\$', 'echo ^\\^$'],
            'Semicolon'              => ['echo Dangerous; rm -rf /', 'echo Dangerous^; rm -rf /'],
            'Newline'                => ["echo Hello\nWorld", "echo Hello^\nWorld"],
            'Multiple special chars' => ['echo \'Single\' "Double"', 'echo ^\'Single^\' ^"Double^"'],
            'Multiple commands'      => ['echo \'Single\' & echo "Double"', 'echo ^\'Single^\' ^& echo ^"Double^"'],
            'Special characters'     => ['echo !@#$%^&*()[]{}', 'echo ^!@^#^$^%^^^&^*^(^)^[^]^{^}'],
            'Non-ASCII characters'   => ["echo \xFF", "echo ^\xFF"],
        ];
    }

    #[DataProvider('escapeshellcmdOsUnixProvider')]
    public function testEscapeshellcmdOsUnix(string $input, string $expected): void
    {
        $this->assertSame($expected, DropletManager\escapeshellcmd_os($input, false));
    }

    #[DataProvider('escapeshellcmdOsWindowsProvider')]
    public function testEscapeshellcmdOsWindows(string $input, string $expected): void
    {
        $this->assertSame($expected, DropletManager\escapeshellcmd_os($input, true));
    }

    public function testEscapeshellcmdOsAutodetectOS(): void
    {
        $input  = 'echo Hello & World';
        $result = DropletManager\escapeshellcmd_os($input);

        if (PHP_OS_FAMILY === 'Windows') {
            $this->assertSame('echo Hello ^& World', $result);
        } else {
            $this->assertSame('echo Hello \\& World', $result);
        }
    }

    public function testEscapeshellcmdOsWithNullByte(): void
    {
        $this->expectException(\ValueError::class);
        DropletManager\escapeshellcmd_os("Hello\0World");
    }

    #[DataProvider('escapeshellcmdOsUnixProvider')]
    public function testEscapeshellcmdLinux(string $input, string $expected): void
    {
        $this->assertSame($expected, DropletManager\escapeshellcmd_linux($input));
    }

    #[DataProvider('escapeshellcmdOsWindowsProvider')]
    public function testEscapeshellcmdWindows(string $input, string $expected): void
    {
        $this->assertSame($expected, DropletManager\escapeshellcmd_windows($input));
    }

    public static function escapeSingleQuotesForSedProvider()
    {
        return [
            ["It's a test", "It'\\''s a test"],
            ['No quotes here', 'No quotes here'],
            ["Multiple'quotes'in'a'row", "Multiple'\\''quotes'\\''in'\\''a'\\''row"],
            ["'", "'\\''"],
            ["''", "'\\'''\\''"],
            ["'''", "'\\'''\\'''\\''"],
            ["Ends with quote'", "Ends with quote'\\''"],
        ];
    }

    #[DataProvider('escapeSingleQuotesForSedProvider')]
    public function testEscapeSingleQuotesForSed($input, $expected)
    {
        $this->assertEquals($expected, DropletManager\escape_single_quotes_for_sed($input));
    }

    public static function trimIfStringProvider()
    {
        // For callable expected values, is_callable() is used to check the result
        return [
            'Trims string'               => ['  Hello, World!  ', 'Hello, World!'],
            'Trims string with tabs'     => ["\tHello, World!\t", 'Hello, World!'],
            'Trims string with newlines' => ["\nHello, World!\n", 'Hello, World!'],
            'Already trimmed string'     => ['Hello, World!', 'Hello, World!'],
            'Empty string'               => ['', ''],
            'String of spaces'           => ['     ', ''],
            'Integer'                    => [42, 42],
            'Float'                      => [3.14, 3.14],
            'Boolean true'               => [true, true],
            'Boolean false'              => [false, false],
            'Null'                       => [null, null],
            'Array'                      => [[1, 2, 3], [1, 2, 3]],
            'Object'                     => [new \stdClass(), new \stdClass()],
            'Resource'                   => [fopen('php://memory', 'r'), function ($value) {
                return is_resource($value);
            }],
            'Closure' => [function () {}, function ($value) {
                return $value instanceof \Closure;
            }],
        ];
    }

    #[DataProvider('trimIfStringProvider')]
    public function testTrimIfString($input, $expected)
    {
        $result = DropletManager\trim_if_string($input);

        if (is_callable($expected)) {
            $this->assertTrue($expected($result));
        } elseif (is_object($expected)) {
            $this->assertEquals(get_class($expected), get_class($result));
        } else {
            $this->assertSame($expected, $result);
        }
    }

    public function testTrimIfStringWithCustomObject()
    {
        $obj = new class () {
            public $property = 'value';
        };

        $result = DropletManager\trim_if_string($obj);

        $this->assertInstanceOf(get_class($obj), $result);
        $this->assertSame('value', $result->property);
    }

    public function testTrimIfStringWithStringable()
    {
        $stringable = new class () implements \Stringable {
            public function __toString()
            {
                return '  Stringable  ';
            }
        };

        $result = DropletManager\trim_if_string($stringable);

        $this->assertInstanceOf(get_class($stringable), $result);
        $this->assertSame('  Stringable  ', (string)$result);
    }
}
