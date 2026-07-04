<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign\Tests;

use K2gl\Dsse\Ed25519Signer;
use K2gl\RekorClient\KeyDetails;
use K2gl\SigstoreSign\Exception\SigningException;
use K2gl\SigstoreSign\SigningKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(SigningKey::class)]
final class SigningKeyTest extends TestCase
{
    public function testExposesRekorVerifierAndBundleIdentityForAPublicKey(): void
    {
        $key = SigningKey::publicKey($this->signer(), 'pub-der', KeyDetails::PKIX_ED25519, 'hint');

        fact($key->rekorVerifier()->toArray()['publicKey']['rawBytes'])->is(base64_encode('pub-der'));
        fact($key->bundleIdentity()->toArray()['publicKey']['hint'])->is('hint');
    }

    public function testExposesCertificateForBothRekorAndBundle(): void
    {
        $key = SigningKey::certificate($this->signer(), 'cert-der', KeyDetails::PKIX_ED25519);

        fact($key->rekorVerifier()->toArray()['x509Certificate']['rawBytes'])->is(base64_encode('cert-der'));
        fact($key->bundleIdentity()->toArray()['certificate']['rawBytes'])->is(base64_encode('cert-der'));
    }

    public function testSignDelegatesToTheSigner(): void
    {
        $key = SigningKey::publicKey($this->signer(), 'pub', KeyDetails::PKIX_ED25519, 'hint');

        // Deterministic Ed25519: signing the same message twice matches.
        fact($key->sign('message'))->is($key->sign('message'));
    }

    public function testRejectsEmptyPublicKey(): void
    {
        $this->expectException(SigningException::class);
        SigningKey::publicKey($this->signer(), '', KeyDetails::PKIX_ED25519, 'hint');
    }

    public function testRejectsEmptyHint(): void
    {
        $this->expectException(SigningException::class);
        SigningKey::publicKey($this->signer(), 'pub', KeyDetails::PKIX_ED25519, '');
    }

    public function testRejectsEmptyCertificate(): void
    {
        $this->expectException(SigningException::class);
        SigningKey::certificate($this->signer(), '', KeyDetails::PKIX_ED25519);
    }

    private function signer(): Ed25519Signer
    {
        return new Ed25519Signer(sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair()), 'kid');
    }
}
