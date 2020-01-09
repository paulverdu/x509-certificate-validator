<?php

namespace PVerdu\x509CertificateValidator\Rule;

use phpseclib\File\X509;
use PVerdu\x509CertificateValidator\Exception\CertificateException;
use PVerdu\x509CertificateValidator\Helper\X509CertificateHelper;
use PVerdu\x509CertificateValidator\X509Certificate;
use Symfony\Component\Finder\Finder;

class ValidHierarchyRule implements ValidatorRule
{
    /*** @var array */
    private $trustStorePaths;

    public function __construct(array $trustStorePaths)
    {
        $this->trustStorePaths = $trustStorePaths;
    }

    /***
     * @param X509Certificate $x509Certificate
     * @return void
     */
    public function verify(X509Certificate $x509Certificate): void
    {
        $rootCertificate = $this->getRootCertificate($x509Certificate);

        foreach ($this->getCACertificatesFromTrustStore() as $caCertificate) {
            $rootCertificate->loadCA(file_get_contents($caCertificate));
        }

        if (!@$rootCertificate->validateSignature()) {
            throw CertificateException::invalidSignature();
        }
    }

    /**
     * @param X509Certificate $x509Certificate
     * @return bool|X509
     */
    private function getRootCertificate(X509Certificate $x509Certificate)
    {
        $currentCertificate = X509CertificateHelper::loadX509($x509Certificate);

        do {
            $parentCertificate = X509CertificateHelper::getIssuerCertificate($currentCertificate);
            if ($parentCertificate === null) {
                break;
            }

            $currentCertificate->loadCA($parentCertificate);
            if (!@$currentCertificate->validateSignature()) {
                throw CertificateException::invalidSignature();
            }

            $currentCertificate = X509CertificateHelper::loadX509($parentCertificate);
        } while ($parentCertificate !== null);

        return $currentCertificate;
    }

    /**
     * @return array
     */
    private function getCACertificatesFromTrustStore(): array
    {
        $files = [];
        $finder = new Finder();
        foreach ($this->trustStorePaths as $path) {
            $finder->in($path)->files();

            foreach ($finder as $file) {
                $files[] = $file->getRealPath();
            }
        }

        return $files;
    }
}
