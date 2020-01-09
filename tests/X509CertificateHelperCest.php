<?php

namespace PVerdu\Tests;

use phpseclib\File\X509;
use phpseclib\Math\BigInteger;
use PVerdu\x509CertificateValidator\Helper\X509CertificateHelper;
use PVerdu\x509CertificateValidator\X509Certificate;

class X509CertificateHelperCest extends TestBase
{
    public function testLoadingX509()
    {
        $x509Certificate = new X509Certificate($this->getCertificate('valid_till_2046-02-09.pem'));
        $x509 = X509CertificateHelper::loadX509($x509Certificate);

        $this->assertInstanceOf(X509::class, $x509);
    }

    public function testLoadingX509Certificate()
    {
        $x509 = X509CertificateHelper::loadX509($this->getCertificate('valid_till_2046-02-09.pem'));

        $this->assertInstanceOf(X509::class, $x509);
    }

    public function testGetEmptyArrayOfCrlUris()
    {
        $x509Certificate = new X509Certificate($this->getCertificate('valid_till_2046-02-09.pem'));
        $crlUris = X509CertificateHelper::getCrlUris($x509Certificate);

        $this->assertEquals([], $crlUris);
    }

    public function testGetArrayOfCrlUris()
    {
        $crlUris = ['https://uri-one.nl', 'https://uri-two.nl'];
        $x509Certificate = $this->generateCertificateWithCrlUris($crlUris);
        $crlUrisFromCertificate = X509CertificateHelper::getCrlUris($x509Certificate);

        $this->assertEquals($crlUris, $crlUrisFromCertificate);
    }

    public function testGetSerialNumber()
    {
        $number = '8127340310293';
        $serialNumber = new BigInteger($number, 10);
        $x509Certificate = $this->generateCertificateWithSerialNumber($number);
        $serialNumberFromCertificate = X509CertificateHelper::getSerialNumber($x509Certificate);

        $this->assertEquals($serialNumber, $serialNumberFromCertificate);
    }

    public function testIssuerCertificateFromSelfSignedCertificate()
    {
        $x509Certificate = new X509Certificate($this->getCertificate('valid_till_2046-02-09.pem'));
        $issuerCertificate = X509CertificateHelper::getIssuerCertificate($x509Certificate);

        $this->assertEquals(null, $issuerCertificate);
    }

    public function testIssuerCertificateFromValidPkioCertificate()
    {
        $x509Certificate = new X509Certificate($this->getCertificate('pkio.crt'));
        $issuerCertificate = X509CertificateHelper::getIssuerCertificate($x509Certificate);

        $this->assertNotNull($issuerCertificate);
    }

    public function testIssuerCertificateFromValidOdocCertificate()
    {
        $x509Certificate = new X509Certificate($this->getCertificate('odoc.crt'));
        $issuerCertificate = X509CertificateHelper::getIssuerCertificate($x509Certificate);

        $this->assertNull($issuerCertificate);
    }
}
