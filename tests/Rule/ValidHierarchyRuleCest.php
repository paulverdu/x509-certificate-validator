<?php

namespace PVerdu\Tests\Rule;

use PVerdu\Tests\TestBase;
use PVerdu\x509CertificateValidator\Exception\CertificateException;
use PVerdu\x509CertificateValidator\Rule\ValidHierarchyRule;
use PVerdu\x509CertificateValidator\X509Certificate;

class ValidHierarchyRuleCest extends TestBase
{
    public function testNonGovermentCertificate()
    {
        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage(CertificateException::invalidSignature()->getMessage());

        $validHierarchyRule = new ValidHierarchyRule($this->getTrustStorePaths());
        $x509Certificate = new X509Certificate($this->getCertificate('non-goverment-certificate.pem'));

        $validHierarchyRule->verify($x509Certificate);
    }
}
