<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign\Internal;

use K2gl\SigstoreSign\Exception\FulcioException;

/**
 * Converts a PEM block to its raw DER bytes — strips the armor and decodes the
 * base64 body. Fulcio returns certificates as PEM; bundles and Rekor want DER.
 *
 * @internal
 */
final class Pem
{
    public static function toDer(string $pem): string
    {
        $body = (string) preg_replace('/-----(BEGIN|END)[^-]+-----|\s/', '', $pem);
        $der = base64_decode($body, true);

        if ($der === false || $der === '') {
            throw new FulcioException('Certificate PEM is not valid base64.');
        }

        return $der;
    }
}
