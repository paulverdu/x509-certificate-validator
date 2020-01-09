<?php

namespace PVerdu\x509CertificateValidator\Rule;

use PVerdu\x509CertificateValidator\X509Certificate;

interface ValidatorRule
{
    /**
     * @param X509Certificate $x509Certificate
     */
    public function verify(X509Certificate $x509Certificate): void;
}
