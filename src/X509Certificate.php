<?php

namespace PVerdu\x509CertificateValidator;

use DateTime;
use Exception;
use PVerdu\x509CertificateValidator\Exception\CertificateException;
use PVerdu\x509CertificateValidator\Transformer\CertificateTransformer;

class X509Certificate
{
    public const TIMESTAMP_VALID_FROM_KEY = 'validFrom_time_t';
    public const TIMESTAMP_VALID_TO_KEY = 'validTo_time_t';

    /** @var array */
    private $certificateData;

    /** @var string */
    private $x509CertificateString;

    public function __construct($x509CertificateString)
    {
        if (
            !strpos($x509CertificateString, CertificateTransformer::PEM_HEADER)
            && !strpos($x509CertificateString, CertificateTransformer::PEM_FOOTER)
        ) {
            $x509CertificateString = CertificateTransformer::addHeaderAndFooter($x509CertificateString);
        }

        $this->certificateData = $this->readAndParseCertificateString($x509CertificateString);
        $this->x509CertificateString = $x509CertificateString;
    }

    /**
     * @return string
     */
    public function __toString(): string
    {
        return $this->x509CertificateString;
    }

    /**
     * @return DateTime|null
     * @throws Exception
     */
    public function getStartDate(): ?DateTime
    {
        if (!array_key_exists(self::TIMESTAMP_VALID_FROM_KEY, $this->certificateData)) {
            return null;
        }

        return (new DateTime())->setTimestamp($this->certificateData[self::TIMESTAMP_VALID_FROM_KEY]);
    }

    /**
     * @return DateTime|null
     * @throws Exception
     */
    public function getEndDate(): ?DateTime
    {
        if (!array_key_exists(self::TIMESTAMP_VALID_TO_KEY, $this->certificateData)) {
            return null;
        }

        return (new DateTime())->setTimestamp($this->certificateData[self::TIMESTAMP_VALID_TO_KEY]);
    }

    /**
     * @return array
     */
    public function getAll(): array
    {
        return $this->certificateData;
    }

    /**
     * @param $x509CertificateString
     * @return array|false
     */
    private function readAndParseCertificateString($x509CertificateString)
    {
        try {
            return openssl_x509_parse(openssl_x509_read($x509CertificateString));
        } catch (Exception $e) {
            throw CertificateException::invalidCertificate();
        }
    }
}
