<?php

namespace Fiea\classes;

class IDigitalDiscovery {
    public string $issuer;
    public string $jwks_uri;
    public string $token_endpoint;
    public array $claims_supported;
    public array $scopes_supported;
    public ?string $userinfo_endpoint;
    public string $end_session_endpoint;
    public array $claim_types_supported;
    public array $grant_types_supported;
    public string $authorization_endpoint;
    public array $subject_types_supported;
    public array $response_modes_supported;
    public array $response_types_supported;
    public bool $claims_parameter_supported;
    public bool $request_parameter_supported;
    public bool $backchannel_logout_supported;
    public ?string $credential_manager_endpoint;
    public bool $request_uri_parameter_supported;
    public bool $require_request_uri_registration;
    public array $code_challenge_methods_supported;
    public array $dpop_signing_alg_values_supported;
    public bool $backchannel_logout_session_supported;
    public array $id_token_signing_alg_values_supported;
    public array $token_endpoint_auth_methods_supported;
    public array $request_object_signing_alg_values_supported;
    public bool $authorization_response_iss_parameter_supported;
    public static string $PATHNAME = 'sso/oidc/.well-known/openid-configuration';

    public function __construct($discovery) {
        $this->issuer = $discovery->issuer;
        $this->jwks_uri = $discovery->jwks_uri;
        $this->token_endpoint = $discovery->token_endpoint;
        $this->claims_supported = $discovery->claims_supported;
        $this->scopes_supported = $discovery->scopes_supported;
        $this->end_session_endpoint = $discovery->end_session_endpoint;
        $this->claim_types_supported = $discovery->claim_types_supported;
        $this->grant_types_supported = $discovery->grant_types_supported;
        $this->userinfo_endpoint = $discovery->userinfo_endpoint ?? null;
        $this->authorization_endpoint = $discovery->authorization_endpoint;
        $this->subject_types_supported = $discovery->subject_types_supported;
        $this->response_modes_supported = $discovery->response_modes_supported;
        $this->response_types_supported = $discovery->response_types_supported;
        $this->claims_parameter_supported = $discovery->claims_parameter_supported;
        $this->request_parameter_supported = $discovery->request_parameter_supported;
        $this->backchannel_logout_supported = $discovery->backchannel_logout_supported;
        $this->request_uri_parameter_supported = $discovery->request_uri_parameter_supported;
        $this->credential_manager_endpoint = $discovery->credential_manager_endpoint ?? null;
        $this->require_request_uri_registration = $discovery->require_request_uri_registration;
        $this->code_challenge_methods_supported = $discovery->code_challenge_methods_supported;
        $this->dpop_signing_alg_values_supported = $discovery->dpop_signing_alg_values_supported;
        $this->backchannel_logout_session_supported = $discovery->backchannel_logout_session_supported;
        $this->id_token_signing_alg_values_supported = $discovery->id_token_signing_alg_values_supported;
        $this->token_endpoint_auth_methods_supported = $discovery->token_endpoint_auth_methods_supported;
        $this->request_object_signing_alg_values_supported = $discovery->request_object_signing_alg_values_supported;
        $this->authorization_response_iss_parameter_supported = $discovery->authorization_response_iss_parameter_supported;
    }
}