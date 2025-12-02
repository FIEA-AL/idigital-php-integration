# IDigital PHP Integration

[![License][license-badge]][license-url]

> IDigital OpenID Connect integration for PHP

## Usage

- Install package

```bash
# Composer
$ composer config repositories.idigital-php-integration vcs https://github.com/FIEA-AL/idigital-php-integration.git
$ composer require fiea-al/idigital-php-integration:2.0.0
```

&nbsp;

- Import package

```php
use Fiea\classes\IDigitalOptions;
use Fiea\IDigital;
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
<?php

namespace App\Controller;

use App\Controller\LoginController;
use Slim\Http\Request;
use Slim\Http\Response;
use Fiea\classes\IDigitalOptions;
use Fiea\IDigital;
use Firebase\JWT\JWT;

class IDigitalController {

    public static ?IDigitalOptions $iDigitalOptions = null;
    public static ?IDigital $iDigital = null;

    public function __construct() {

        JWT::$leeway = (intval(getenv('JWT_LEEWAY')) ?? 0);

        if(self::$iDigitalOptions == null) {
            self::$iDigitalOptions = new IDigitalOptions([
                'issuer'                => getenv('SSO_I_DIGITAL_ENDPOINT'),
                'clientId'              => getenv('SSO_I_DIGITAL_CLIENT_ID'),
                'redirectUri'           => getenv('SS0_I_DIGITAL_REDIRECT_URI'),
                'applicationHost'       => getenv('SS0_I_DIGITAL_RESOURCE'),
                'scopes'                => explode(" ", getenv('SSO_I_DIGITAL_SCOPE')),
                'postLogoutRedirectUri' => getenv('SS0_I_DIGITAL_POST_LOGOUT_URI')
            ]);
        }

        if(self::$iDigital == null) {
            self::$iDigital = IDigital::create(self::$iDigitalOptions);
        }
    }

    /**
     * Login no SSO do iDigital
     */
    public function iDigitalLoginPage(Request $request, Response $response, $args) {
        return $response->withRedirect(self::$iDigital->getAuthorizationCodeFlow()->authorize());
    }

    /**
     * Callback de retorno do login no SSO do iDigital
     * Integra o login do iDigital com o login interno da aplicação
     */
    public function iDigitalLoginCallbackPage(Request $request, Response $response, $args) {
        try {
            // Buscar parâmetros da requisição
            $get = $request->getQueryParams();
            $code = isset($get['code']) ? $get['code'] : null;
            $state = isset($get['state']) ? $get['state'] : null;

            // Processar callback do iDigital
            $idigitalToken = self::$iDigital->getAuthorizationCodeFlow()->callback(
                $code,
                getenv('SSO_I_DIGITAL_ENDPOINT'),
                $state
            );

            // Processar login interno
            $loginController = new LoginController();
            $loginResult = $loginController->loginIDigital();

            if ($loginResult['status'] === 'success') {
                // Redirecionar para o frontend com o token
                $frontendUrl = getenv('APP_HOST') . '/login?token=' . urlencode($loginResult['token']);
                return $response->withRedirect($frontendUrl);
            } else {
                // Redirecionar para o frontend com erro
                $frontendUrl = getenv('APP_HOST') . '/login?error=' . urlencode($loginResult['message']);
                return $response->withRedirect($frontendUrl);
            }

        } catch (\Throwable $th) {
            // Redirecionar para o frontend com erro
            $frontendUrl = getenv('APP_HOST') . '/login?error=' . urlencode('Erro interno no login IDigital');
            return $response->withRedirect($frontendUrl);
        }
    }

    /**
     * Verificar status da autenticação com o SSO do IDigital
     */
    public function iDigitalIsAuthenticated() {
        return self::$iDigital->getAuthorizationCodeFlow()->isAuthenticated();
    }

    /**
     * Logout do SSO do iDigital
     */
    public function iDigitalLogoutPage(Request $request, Response $response, $args) {
        $redirect = self::$iDigital->getAuthorizationCodeFlow()->logout();
        return $response->withRedirect($redirect);
    }

    /**
     * Callback do logout do iDigital
     */
    public function iDigitalLogoutCallbackPage(Request $request, Response $response, $args) {
        return $response->withRedirect('');
    }

    /**
     * Backchannel logout do iDigital
     */
    public function iDigitalLogoutBackchannelPage(Request $request, Response $response, $args) {
        return $response->withRedirect('');
    }
}
```

&nbsp;

- Environment Variables Required

```bash
# IDigital SSO Configuration
SSO_I_DIGITAL_ENDPOINT=https://sso<prod|homo|dev>.idigital.sistemafiea.com.br
SSO_I_DIGITAL_CLIENT_ID=<your-client-id>
SS0_I_DIGITAL_REDIRECT_URI=<your-application-host>/idigital/auth/callback
SS0_I_DIGITAL_RESOURCE=<your-application-host-with-protocol>
SSO_I_DIGITAL_SCOPE=openid profile email document
SS0_I_DIGITAL_POST_LOGOUT_URI=<your-application-host>/idigital/auth/logout/callback

# Application Configuration
APP_HOST=<your-frontend-url>
JWT_LEEWAY=0
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

## License

[MIT](https://github.com/FIEA-AL/idigital-php-integration/blob/main/LICENSE)

[license-badge]: https://img.shields.io/badge/License-MIT-yellow.svg
[license-url]: https://opensource.org/licenses/MIT
