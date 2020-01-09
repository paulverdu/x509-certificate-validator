<?php

namespace PVerdu\x509CertificateValidator\Exception;

use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

class CertificateException extends BadRequestHttpException
{
    public static function noCertificateFound(): self
    {
        return new self('Certificate could not be found.');
    }

    public static function invalidCertificate(): self
    {
        return new self('Certificate could not be read and parsed.');
    }

    public static function expiredCertificate(): self
    {
        return new self('Certificate is expired.');
    }

    public static function revokedCertificate(): self
    {
        return new self('Certificate is revoked.');
    }

    public static function missingSerialNumberInCertificate(): self
    {
        return new self('Certificate has no serial number.');
    }

    public static function invalidSignature(): self
    {
        return new self('Certificate does not have a valid signature.');
    }
}
