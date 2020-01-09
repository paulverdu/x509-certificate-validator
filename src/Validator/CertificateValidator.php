<?php

namespace PVerdu\x509CertificateValidator\Validator;

use PVerdu\x509CertificateValidator\Rule\ValidatorRule;
use PVerdu\x509CertificateValidator\X509Certificate;

class CertificateValidator
{
    /*** @var ValidatorRule[] */
    private $validatorRules;

    public function __construct(array $validatorRules)
    {
        $this->validatorRules = $validatorRules;
    }

    public function validate(string $certificateString): void
    {
        $x509Certificate = new X509Certificate($certificateString);

        foreach ($this->validatorRules as $validatorRule) {
            $validatorRule->verify($x509Certificate);
        }
    }
}
