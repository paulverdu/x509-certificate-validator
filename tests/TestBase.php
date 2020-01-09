<?php

namespace PVerdu\Tests;

use phpseclib\Crypt\RSA;
use phpseclib\File\X509;
use PHPUnit\Framework\TestCase;

class TestBase extends TestCase
{
    public const CERTIFICATE_DIRECTORY = __DIR__ . '/data/certificates';
    public const CACERTS_TEST_DIRECTORY = __DIR__ . '/data/cacerts';

    /**
     * @var RSA
     */
    private $rsaPublicKey;
    /**
     * @var RSA
     */
    private $rsaPrivateKey;
    /**
     * @var X509
     */
    private $issuerCertificate;

    public function setUp(): void
    {
        $rsa = new RSA();
        $keys = $rsa->createKey();
        $this->rsaPublicKey = new RSA();
        $this->rsaPublicKey->loadKey($keys['publickey']);
        $this->rsaPublicKey->setPublicKey();
        $this->rsaPrivateKey = new RSA();
        $this->rsaPrivateKey->loadKey($keys['privatekey']);
        $this->issuerCertificate = new X509();
        $this->issuerCertificate->setPrivateKey($this->rsaPrivateKey);
        $this->issuerCertificate->setDN('/O=test org');
    }

    public function getCertificate($name)
    {
        return file_get_contents(self::CERTIFICATE_DIRECTORY . '/' . $name);
    }

    /**
     * @param array $crlUris
     * @param string $serialNumber
     * @return mixed
     */
    public function generateCertificateWithCrlUris(array $crlUris, $serialNumber = '0000007')
    {
        $x509 = new X509();
        $x509->loadX509($this->generateCertificateWithSerialNumber($serialNumber));
        $distributionPoints = [];
        for ($i = 0; $i < count($crlUris); $i++) {
            $distributionPoints[$i] = [
                'distributionPoint' => [
                    'fullName' => [
                        ['uniformResourceIdentifier' => $crlUris[$i]]
                    ]
                ]
            ];
        }
        $x509->setExtension('id-ce-cRLDistributionPoints', $distributionPoints);

        return $x509->saveX509(
            $x509->sign($this->issuerCertificate, $x509)
        );
    }

    /**
     * @param string|null $serialNumber
     * @return mixed
     */
    public function generateCertificateWithSerialNumber($serialNumber)
    {
        $x509 = new X509();
        $x509->setPublicKey($this->rsaPublicKey);
        $x509->setDN('/CN=www.example.org');
        $x509->setStartDate('-1 day');
        $x509->setEndDate('+1 year');
        $x509->setSerialNumber($serialNumber, 10);

        return $x509->saveX509(
            $x509->sign($this->issuerCertificate, $x509)
        );
    }

    /**
     * @param array $revokedSerialNumbers
     * @return string
     */
    public function haveACrlWithSerialNumbers(array $revokedSerialNumbers)
    {
        $crl = new X509();
        $crl->loadCRL(
            $crl->saveCRL($crl->signCRL($this->issuerCertificate, $crl))
        );
        foreach ($revokedSerialNumbers as $revokedSerialNumber) {
            $crl->setRevokedCertificateExtension($revokedSerialNumber, 'id-ce-cRLReasons', 'privilegeWithdrawn');
        }
        $crl->setSerialNumber('0000007', 10);
        $crl->setEndDate('+1 year');
        $crlData = $crl->signCRL($this->issuerCertificate, $crl);

        return $crl->saveCrl($crlData);
    }

    /**
     * @param bool $testCertificates
     * @return array
     */
    public function getTrustStorePaths($testCertificates = false)
    {
        return [self::CACERTS_TEST_DIRECTORY];
    }
}
