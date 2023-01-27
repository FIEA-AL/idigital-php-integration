# IDigital PHP Integration

[![License][license-badge]][license-url]

> IDigital OpenID Connect integration for PHP

## Usage

- Install package

```bash
# Composer
$ composer config repositories.idigital-php-integration vcs https://github.com/FIEA-AL/idigital-php-integration.git
$ composer require fiea-al/idigital-php-integration:1.1.0
```

&nbsp;
- Import package
```php
use Fiea\classes\IDigitalConfig as IDigitalConfig;
use Fiea\IDigital as IDigital;
```

&nbsp;
- Instantiate package
```php
$this->idigital = IDigital::create(new IDigitalConfig([
    'postLogoutRedirectUri' => '<your-application-host>/idigital/auth/logout/callback',
    'issuer' => 'https://sso<prod|homo|dev>.idigital.sistemafiea.com.br',
    'redirectUri' => '<your-application-host>/idigital/auth/callback',
    'applicationHost' => '<your-application-host-with-protocol>',
    'scopes' => 'openid profile email document',
    'clientId' => '<your-client-id>'
]));
```

&nbsp;
- Slim Framework Example
```php
use Fiea\classes\IDigitalConfig as IDigitalConfig;
use Fiea\IDigital as IDigital;

class IDigitalController {
    public ?IDigital $idigital = null;

    public function __construct() {
        $this->idigital = IDigital::create(new IDigitalConfig([
            'postLogoutRedirectUri' => '<your-application-host>/idigital/auth/logout/callback',
            'issuer' => 'https://sso<prod|homo|dev>.idigital.sistemafiea.com.br',
            'redirectUri' => '<your-application-host>/idigital/auth/callback',
            'applicationHost' => '<your-application-host-with-protocol>',
            'scopes' => 'openid profile email document',
            'clientId' => '<your-client-id>'
        ]));
    }

    public function authorize(Request $request, Response $response) {
        $url = $this->idigital->authorize(null);
        return $response->withRedirect($url);
    }

    public function callback(Request $request, Response $response) {
        $queryParams = $request->getQueryParams();
        $state = $queryParams['state'] ?? null;
        $issuer = $queryParams['iss'] ?? null;
        $code = $queryParams['code'] ?? null;

        $this->idigital->callback($code, $issuer, $state, null);
        return $response->withRedirect('/');
    }

    public function logout(Request $request, Response $response) {
        $url = $this->idigital->logout(null, fn() => session_destroy());
        return $response->withRedirect($url);
    }

    public function logoutCallback(Request $request, Response $response) {
        return $response->withRedirect('/');
    }
}
```


## Development

- Clone the repo

```bash
$ git clone https://github.com/FIEA-AL/idigital-php-integration.git
```

- Install dependencies

```bash
# Composer
$ composer install
```

## Author

[Matheus Melo](https://www.linkedin.com/in/matheus-melo-7198901a4)

## Contributors
- [Bruno Pereira](https://www.linkedin.com/in/batlopes)
- [Vitor Barcelos](https://www.linkedin.com/in/vitorbarcelos)
- [Genildo Rodrigues](https://www.linkedin.com/in/genildorodrigues)

## License

[MIT](https://github.com/FIEA-AL/idigital-php-integration/blob/main/LICENSE)

[license-badge]: https://img.shields.io/badge/License-MIT-yellow.svg
[license-url]: https://opensource.org/licenses/MIT
