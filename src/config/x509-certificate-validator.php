<?php

use PVerdu\x509CertificateValidator\Rule\NotRevokedRule;
use PVerdu\x509CertificateValidator\Rule\ValidCertificateRule;
use PVerdu\x509CertificateValidator\Rule\ValidHierarchyRule;

return [
    /**
     * From which request source should the certificate be retrieved from
     *
     * Available types: server, header
     */
    'source' => 'server',
    /**
     * The key where the certificate can be found in the source
     */
    'source_key' => 'SSL_CERT',
    /**
     * Should the source be unescaped before validation
     * Useful when using for example $ssl_client_escaped_cert in NGINX
     */
    'source_unescape' => true,
    /**
     * Which rules should be checked when running the middleware
     */
    'enabled_rules' => [
        NotRevokedRule::class,
        ValidCertificateRule::class,
        ValidHierarchyRule::class,
    ],
    /**
     * Paths to trust stores
     */
    'trust_store_paths' => [
        config_path('cacerts')
    ]
];
