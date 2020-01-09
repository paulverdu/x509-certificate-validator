<?php

namespace PVerdu\Tests\Rule;

use PVerdu\Tests\TestBase;
use PVerdu\x509CertificateValidator\Exception\CertificateException;
use PVerdu\x509CertificateValidator\Rule\ValidCertificateRule;
use PVerdu\x509CertificateValidator\X509Certificate;

class ValidCertificateRuleCest extends TestBase
{
    public function testExpiredCertificate()
    {
        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage(CertificateException::expiredCertificate()->getMessage());

        $validCertificateRule = new ValidCertificateRule();
        $x509Certificate = new X509Certificate($this->getCertificate('valid_till_2018-09-26.pem'));

        $validCertificateRule->verify($x509Certificate);
    }

    public function testValidCertificate()
    {
        $validCertificateRule = new ValidCertificateRule();
        $x509Certificate = new X509Certificate($this->getCertificate('valid_till_2046-02-09.pem'));

        $validCertificateRule->verify($x509Certificate);

        $this->assertTrue(true);
    }
}
