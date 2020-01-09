<?php

namespace PVerdu\x509CertificateValidator;

use Illuminate\Support\ServiceProvider;
use PVerdu\x509CertificateValidator\Rule\ValidHierarchyRule;
use PVerdu\x509CertificateValidator\Validator\CertificateValidator;

class x509CertificateValidatorServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__ . '/config/x509-certificate-validator.php',
            'x509-certificate-validator'
        );

        $this->app
            ->when(ValidHierarchyRule::class)
            ->needs('$trustStorePaths')
            ->give(
                $this->app
                    ->get('config')
                    ->get('x509-certificate-validator.trust_store_paths')
            );

        $this->app->bind(
            CertificateValidator::class,
            function () {
                return new CertificateValidator(
                    array_map(
                        function ($rule) {
                            return $this->app->make($rule);
                        },
                        $this->app
                            ->get('config')
                            ->get('x509-certificate-validator.enabled_rules')
                    )
                );
            }
        );
    }

    public function boot()
    {
        $this->publishes(
            [
                __DIR__ . '/config/x509-certificate-validator.php' => config_path('x509-certificate-validator.php'),
            ]
        );
    }
}
