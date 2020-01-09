<?php

namespace PVerdu\x509CertificateValidator\Rule;

use PVerdu\x509CertificateValidator\Exception\CertificateException;
use PVerdu\x509CertificateValidator\Helper\X509CertificateHelper;
use PVerdu\x509CertificateValidator\X509Certificate;

class NotRevokedRule implements ValidatorRule
{
    /**
     * @param X509Certificate $x509Certificate
     */
    public function verify(X509Certificate $x509Certificate): void
    {
        $crlUris = X509CertificateHelper::getCrlUris($x509Certificate);
        $serialNumber = X509CertificateHelper::getSerialNumber($x509Certificate);

        if (empty($serialNumber)) {
            throw CertificateException::missingSerialNumberInCertificate();
        }

        foreach ($crlUris as $uri) {
            $certificateRevocationList = X509CertificateHelper::getCrlFromUri($uri);
            if (empty($certificateRevocationList)) {
                continue;
            }

            if ($certificateRevocationList->getRevoked($serialNumber)) {
                throw CertificateException::revokedCertificate();
            }
        }
    }
}
