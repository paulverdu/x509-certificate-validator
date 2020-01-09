<?php

namespace PVerdu\Tests;

use PVerdu\x509CertificateValidator\Transformer\CertificateTransformer;

class CertificateTransformerCest extends TestBase
{
    public function testAddHeaderAndFooter()
    {
        $string = 'testString';
        $expectedString = "-----BEGIN CERTIFICATE-----\ntestString\n-----END CERTIFICATE-----";

        $transformedString = CertificateTransformer::addHeaderAndFooter($string);
        $this->assertEquals($expectedString, $transformedString);
    }
}
