<?php

namespace PVerdu\x509CertificateValidator\Middleware;

use Closure;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PVerdu\x509CertificateValidator\Exception\CertificateException;
use PVerdu\x509CertificateValidator\Validator\CertificateValidator;

class CertificateValidatorMiddleware
{
    /**
     * @var CertificateValidator
     */
    private $validator;
    /**
     * @var ConfigRepository
     */
    private $config;

    /**
     * CertificateValidatorMiddleware constructor.
     * @param CertificateValidator $validator
     * @param ConfigRepository $config
     */
    public function __construct(CertificateValidator $validator, ConfigRepository $config)
    {
        $this->validator = $validator;
        $this->config = $config;
    }

    /**
     * @param $request
     * @return string|null
     */
    protected function getCertificate($request): ?string
    {
        if ($this->config->get('x509-certificate-validator.source') === 'server') {
            return $request->server($this->config->get('x509-certificate-validator.source_key'));
        }

        return $request->header($this->config->get('x509-certificate-validator.source_key'));
    }

    /**
     * @param $request
     * @param Closure $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $certificate = $this->getCertificate($request);
        if (empty($certificate)) {
            throw CertificateException::noCertificateFound();
        }

        $this->validator->validate(
            $this->config->get('x509-certificate-validator.source_unescape') ? urldecode($certificate) : $certificate
        );

        return $next($request);
    }
}
