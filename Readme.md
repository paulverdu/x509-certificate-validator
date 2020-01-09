# X.509 Certificate Validator

### Features
- CRL (Certificate Revocation List) validation
- Expiration validation
- Signed by a Trusted CA validation (with self-signed support)

## Requirements
- PHP >=7.2
- Laravel >=6

## Installation
```bash
composer require pverdu/x509-certificate-validator`
```
The service provider should be autodiscovered, if not you can add it to your container using:
```php
// ...
PVerdu\x509CertificateValidator\x509CertificateValidatorServiceProvider::class
// ...
```

## Configuration
Make sure your webserver sends the client certificate to your application either via the headers or the global `$_SERVER` variable.

- For NGINX (http://nginx.org/en/docs/http/ngx_http_ssl_module.html#var_ssl_client_escaped_cert)

Add the `PVerdu\x509CertificateValidator\Middleware\CertificateValidatorMiddleware` to any routes you want the certificate to be validated on per request.

### Publish configuration
If you want to change the configuration, for example to change the trusted certificate store paths, you must publish the configuration using the command below:
```bash
php artisan vendor:publish --provider=PVerdu\\x509CertificateValidator\\x509CertificateValidatorServiceProvider
```
