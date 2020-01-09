<?php

namespace PVerdu\x509CertificateValidator\Rule;

use DateTime;
use Exception;
use PVerdu\x509CertificateValidator\Exception\CertificateException;
use PVerdu\x509CertificateValidator\X509Certificate;

class ValidCertificateRule implements ValidatorRule
{
    /**
     * @param X509Certificate $x509Certificate
     * @throws Exception
     * @throws CertificateException
     */
    public function verify(X509Certificate $x509Certificate): void
    {
        $today = new DateTime();
        if ($today < $x509Certificate->getStartDate() || $today > $x509Certificate->getEndDate()) {
            throw CertificateException::expiredCertificate();
        }
    }
}
