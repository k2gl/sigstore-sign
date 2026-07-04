<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign\Internal;

use K2gl\SigstoreSign\Exception\TimestampException;

/**
 * Just enough DER to build an RFC 3161 TimeStampReq and to pull the
 * TimeStampToken back out of a TimeStampResp. Not a general ASN.1 library — it
 * encodes the handful of types the request needs and reads the two-field
 * response envelope, failing closed on anything unexpected.
 *
 * @internal
 */
final class Der
{
    public static function sequence(string ...$parts): string
    {
        return self::tlv(0x30, implode('', $parts));
    }

    public static function integer(int $value): string
    {
        if ($value < 0) {
            throw new TimestampException('Only non-negative integers are encoded.');
        }
        $bytes = $value === 0 ? "\x00" : ltrim(pack('J', $value), "\x00");

        // A leading bit of 1 would read as negative; pad so it stays positive.
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }

        return self::tlv(0x02, $bytes);
    }

    public static function octetString(string $bytes): string
    {
        return self::tlv(0x04, $bytes);
    }

    /** A DER INTEGER from a big-endian magnitude (e.g. an ECDSA r or s value). */
    public static function integerFromBytes(string $magnitude): string
    {
        $value = ltrim($magnitude, "\x00");

        if ($value === '') {
            $value = "\x00";
        } elseif ((ord($value[0]) & 0x80) !== 0) {
            $value = "\x00" . $value; // keep it positive
        }

        return self::tlv(0x02, $value);
    }

    public static function boolean(bool $value): string
    {
        return self::tlv(0x01, $value ? "\xff" : "\x00");
    }

    public static function null(): string
    {
        return "\x05\x00";
    }

    /** Encode a dotted OID string (e.g. "2.16.840.1.101.3.4.2.1"). */
    public static function oid(string $oid): string
    {
        $parts = array_map('intval', explode('.', $oid));

        if (count($parts) < 2) {
            throw new TimestampException('An OID needs at least two arcs.');
        }
        $body = chr((40 * $parts[0] + $parts[1]) & 0xff);

        foreach (array_slice($parts, 2) as $arc) {
            $body .= self::base128($arc);
        }

        return self::tlv(0x06, $body);
    }

    public static function tlv(int $tag, string $content): string
    {
        return chr($tag & 0xff) . self::length(strlen($content)) . $content;
    }

    public static function length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length & 0xff);
        }
        $bytes = ltrim(pack('N', $length), "\x00");

        return chr((0x80 | strlen($bytes)) & 0xff) . $bytes;
    }

    /**
     * Read the TLV at $offset, returning where its content sits and where the
     * next element starts. Supports the short and long definite-length forms.
     *
     * @return array{tag: int, contentStart: int, contentLen: int, next: int}
     */
    public static function read(string $der, int $offset): array
    {
        if ($offset + 2 > strlen($der)) {
            throw new TimestampException('Truncated DER.');
        }
        $tag = ord($der[$offset]);
        $lengthByte = ord($der[$offset + 1]);
        $cursor = $offset + 2;

        if ($lengthByte < 0x80) {
            $length = $lengthByte;
        } else {
            $count = $lengthByte & 0x7f;

            if ($count === 0 || $count > 4 || $cursor + $count > strlen($der)) {
                throw new TimestampException('Unsupported DER length.');
            }
            $length = 0;

            for ($i = 0; $i < $count; $i++) {
                $length = ($length << 8) | ord($der[$cursor + $i]);
            }
            $cursor += $count;
        }

        if ($cursor + $length > strlen($der)) {
            throw new TimestampException('DER length runs past the end of the data.');
        }

        return ['tag' => $tag, 'contentStart' => $cursor, 'contentLen' => $length, 'next' => $cursor + $length];
    }

    private static function base128(int $value): string
    {
        $out = chr($value & 0x7f);
        $value >>= 7;

        while ($value > 0) {
            $out = chr(0x80 | ($value & 0x7f)) . $out;
            $value >>= 7;
        }

        return $out;
    }
}
