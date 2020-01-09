<?php

namespace PVerdu\Tests\Rule;

use org\bovigo\vfs\vfsStream;
use PVerdu\Tests\TestBase;
use PVerdu\x509CertificateValidator\Exception\CertificateException;
use PVerdu\x509CertificateValidator\Rule\NotRevokedRule;
use PVerdu\x509CertificateValidator\X509Certificate;

class NotRevokedRuleCest extends TestBase
{

    public function testWithUnreachableCrlUri()
    {
        $certificate = new X509Certificate(
            $this->generateCertificateWithCrlUris(['https://non-reachable-uri.nl'])
        );

        $notRevokedRule = new NotRevokedRule();
        $notRevokedRule->verify($certificate);

        $this->assertTrue(true);
    }

    public function testWithNotRevokedCertificate()
    {
        $serialNumbers = ['1234567'];
        $vfs = vfsStream::setup(
            'crls',
            null,
            [
                'certs.crl' => $this->haveACrlWithSerialNumbers($serialNumbers)
            ]
        );

        $crlUri = $vfs->getChild('certs.crl')->url();

        $x509Certificate = new X509Certificate(
            $this->generateCertificateWithCrlUris([$crlUri], '7654321')
        );
        $notRevokedRule = new NotRevokedRule();
        $notRevokedRule->verify($x509Certificate);

        $this->assertTrue(true);
    }

    public function testWithPkioCertificate()
    {
        $x509Certificate = new X509Certificate(
            $this->getCertificate('pkio.crt')
        );
        $notRevokedRule = new NotRevokedRule();
        $notRevokedRule->verify($x509Certificate);

        $this->assertTrue(true);
    }

    public function testWithOdocCertificate()
    {
        $x509Certificate = new X509Certificate(
            $this->getCertificate('pkio.crt')
        );
        $notRevokedRule = new NotRevokedRule();
        $notRevokedRule->verify($x509Certificate);

        $this->assertTrue(true);
    }

    public function testWithRevokedCertificate()
    {
        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage(CertificateException::revokedCertificate()->getMessage());

        $serialNumbers = ['1234567'];
        $vfs = vfsStream::setup(
            'crls',
            null,
            [
                'certs.crl' => $this->haveACrlWithSerialNumbers($serialNumbers)
            ]
        );
        $crlUri = $vfs->getChild('certs.crl')->url();

        $x509Certificate = new X509Certificate(
            $this->generateCertificateWithCrlUris([$crlUri], '1234567')
        );

        $notRevokedRule = new NotRevokedRule();
        $notRevokedRule->verify($x509Certificate);
    }

    public function testCertificateWithMissingSerialNumber()
    {
        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage(CertificateException::missingSerialNumberInCertificate()->getMessage());

        $serialNumbers = ['1234567'];
        $vfs = vfsStream::setup(
            'crls',
            null,
            [
                'certs.crl' => $this->haveACrlWithSerialNumbers($serialNumbers)
            ]
        );
        $crlUri = $vfs->getChild('certs.crl')->url();

        $x509Certificate = new X509Certificate(
            $this->generateCertificateWithCrlUris([$crlUri], null)
        );

        $notRevokedRule = new NotRevokedRule();
        $notRevokedRule->verify($x509Certificate);
    }
}
