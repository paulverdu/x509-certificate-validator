<?php

namespace PVerdu\x509CertificateValidator\Helper;

use phpseclib\File\X509;

/**
 * This class is used to get certain value from the phpseclib's x509 class.
 * All methods are static and can be called with an object of our own
 * x509Certificate class or phpseclib's X509 class.
 */
class X509CertificateHelper
{
    public const EXT_CRL_DISTRIBUTION_POINTS = 'id-ce-cRLDistributionPoints';
    public const ID_PE_AUTHORITY_INFO_ACCESS = 'id-pe-authorityInfoAccess';
    public const ID_AD_CA_ISSUERS = 'id-ad-caIssuers';

    /**
     * Convert X509Certificate to phpseclib's X509 object if it's not already
     * @param string|X509 $x509Certificate
     * @return bool|X509
     */
    public static function loadX509($x509Certificate)
    {
        if ($x509Certificate instanceof X509) {
            return $x509Certificate;
        }

        $certificate = new X509();
        $certificate->loadX509($x509Certificate);

        return $certificate;
    }

    /**
     * Get an array of CRL uri's
     * @param string|X509 $x509Certificate
     * @return array
     */
    public static function getCrlUris($x509Certificate): array
    {
        $x509Certificate = self::loadX509($x509Certificate);
        $extension = $x509Certificate->getExtension(self::EXT_CRL_DISTRIBUTION_POINTS);
        if (empty($extension)) {
            return [];
        }

        $crlUris = [];
        foreach ($extension as $extensionValue) {
            $uniformResourceIdentifier = $extensionValue['distributionPoint']['fullName'][0]['uniformResourceIdentifier'];
            if (!empty($uniformResourceIdentifier)) {
                $crlUris[] = $uniformResourceIdentifier;
            }
        }

        return $crlUris;
    }

    /**
     * @param string|X509 $x509Certificate
     * @return string
     */
    public static function getSerialNumber($x509Certificate): string
    {
        $x509Certificate = self::loadX509($x509Certificate);

        return $x509Certificate->currentCert['tbsCertificate']['serialNumber']->toString();
    }

    /**
     * @param $uri
     * @return bool|X509|null
     */
    public static function getCrlFromUri($uri)
    {
        $crlContents = @file_get_contents($uri);
        if ($crlContents === false) {
            return null;
        }

        $certificateRevocationList = new X509();
        $certificateRevocationList->loadCRL($crlContents);

        return $certificateRevocationList;
    }

    /**
     * @param string|X509 $x509Certificate
     * @return null|string
     */
    public static function getIssuerCertificate($x509Certificate): ?string
    {
        $x509Certificate = self::loadX509($x509Certificate);

        $issuerCertificateUrl = self::getIssuerCertificateUrl($x509Certificate);
        if (empty($issuerCertificateUrl)) {
            return null;
        }

        $issuerCertificate = @file_get_contents($issuerCertificateUrl);
        if ($issuerCertificate === false) {
            return null;
        }

        return $issuerCertificate;
    }

    /**
     * @param string|X509 $x509Certificate
     * @return string|null
     */
    private static function getIssuerCertificateUrl($x509Certificate): ?string
    {
        $x509Certificate = self::loadX509($x509Certificate);
        $extension = $x509Certificate->getExtension(self::ID_PE_AUTHORITY_INFO_ACCESS);
        if (empty($extension)) {
            return null;
        }

        foreach ($extension as $extensionValue) {
            if ($extensionValue['accessMethod'] === self::ID_AD_CA_ISSUERS) {
                return $extensionValue['accessLocation']['uniformResourceIdentifier'];
            }
        }

        return null;
    }
}
