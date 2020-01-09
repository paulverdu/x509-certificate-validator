<?php

namespace PVerdu\x509CertificateValidator\Transformer;

class CertificateTransformer
{
    public const PEM_HEADER = '-----BEGIN CERTIFICATE-----';
    public const PEM_FOOTER = '-----END CERTIFICATE-----';

    /**
     * @param string $x509CertificateString
     * @return string
     */
    public static function addHeaderAndFooter(string $x509CertificateString): string
    {
        $x509CertificateString = trim($x509CertificateString);
        $x509certificate = str_replace(array("\r", "\n"), '', $x509CertificateString);
        return self::PEM_HEADER . "\n" . chunk_split($x509certificate, 64, "\n") . self::PEM_FOOTER;
    }
}
