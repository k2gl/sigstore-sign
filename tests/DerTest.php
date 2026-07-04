<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign\Tests;

use K2gl\SigstoreSign\Exception\TimestampException;
use K2gl\SigstoreSign\Internal\Der;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(Der::class)]
final class DerTest extends TestCase
{
    public function testIntegerEncodesMinimallyAndStaysPositive(): void
    {
        fact(bin2hex(Der::integer(0)))->is('020100');
        fact(bin2hex(Der::integer(1)))->is('020101');
        fact(bin2hex(Der::integer(255)))->is('020200ff'); // pad so the high bit is not read as negative
        fact(bin2hex(Der::integer(256)))->is('02020100');
    }

    public function testKnownOidEncoding(): void
    {
        // id-sha256 = 2.16.840.1.101.3.4.2.1
        fact(bin2hex(Der::oid('2.16.840.1.101.3.4.2.1')))->is('0609608648016503040201');
    }

    public function testBooleanAndNullAndOctetString(): void
    {
        fact(bin2hex(Der::boolean(true)))->is('0101ff');
        fact(bin2hex(Der::boolean(false)))->is('010100');
        fact(bin2hex(Der::null()))->is('0500');
        fact(bin2hex(Der::octetString("\x01\x02")))->is('04020102');
    }

    public function testSequenceWrapsItsParts(): void
    {
        $seq = Der::sequence(Der::integer(1), Der::boolean(true));
        fact(bin2hex($seq))->is('3006' . '020101' . '0101ff');
    }

    public function testLongFormLengthRoundTrips(): void
    {
        $content = str_repeat("\x41", 300);
        $seq = Der::sequence(Der::octetString($content));

        $outer = Der::read($seq, 0);
        fact($outer['tag'])->is(0x30);
        $octet = Der::read($seq, $outer['contentStart']);
        fact($octet['tag'])->is(0x04);
        fact($octet['contentLen'])->is(300);
        fact(substr($seq, $octet['contentStart'], $octet['contentLen']))->is($content);
    }

    public function testReadRejectsTruncatedData(): void
    {
        $this->expectException(TimestampException::class);
        Der::read("\x30", 0);
    }

    public function testReadRejectsLengthPastEnd(): void
    {
        $this->expectException(TimestampException::class);
        Der::read("\x04\x0a\x01", 0); // claims 10 content bytes, only 1 present
    }
}
