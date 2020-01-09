<?php

namespace PVerdu\Tests;

use PVerdu\x509CertificateValidator\Exception\CertificateException;
use PVerdu\x509CertificateValidator\X509Certificate;

class X509CertificateCest extends TestBase
{
    public function testInvalidCertificate()
    {
        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage(CertificateException::invalidCertificate()->getMessage());

        $certificateContents = 'JustSomeRandomContent';
        new X509Certificate($certificateContents);
    }

    public function testValidCertificateWithoutHeaderAndFooter()
    {
        $certificateContents = $this->getCertificate('valid_till_2046-02-09.pem');
        $x509Certificate = new X509Certificate($certificateContents);

        $this->assertInstanceOf(X509Certificate::class, $x509Certificate);
    }

    public function testValidCertificateWithHeaderAndFooter()
    {
        $certificateContents = $this->getCertificate('valid_till_2046-02-09.crt');
        $x509Certificate = new X509Certificate($certificateContents);

        $this->assertInstanceOf(X509Certificate::class, $x509Certificate);
    }

    public function testCertificateString()
    {
        $certificateContents = $this->getCertificate('valid_till_2046-02-09.crt');
        $x509Certificate = new X509Certificate($certificateContents);

        $this->assertEquals($certificateContents, (string)$x509Certificate);
    }

}
