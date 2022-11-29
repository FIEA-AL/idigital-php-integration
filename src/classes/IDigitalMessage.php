<?php

namespace Fiea\classes;

class IDigitalMessage {
    public static string $REQUIRED_SESSION = 'O uso de sessão é obrigatório.';
    public static string $INVALID_JWT = 'O token em análise não é um JWT válido.';
    public static string $DIVERGENT_CLIENT_ID = 'O ID do cliente não pertence ao servidor.';
    public static string $DIVERGENT_NONCE = 'A propriedade nonce enviada difere da armazenada.';
    public static string $DIVERGENT_STATE = 'A propriedade state enviada difere da armazenada.';
    public static string $DIVERGENT_ISSUER = 'A propriedade issuer enviada difere da armazenada.';
    public static string $DIVERGENT_AUDIENCE = 'A propriedade audience enviada difere da armazenada.';
    public static string $JWT_WITHOUT_ALG = 'O JWT não possui uma propriedade alg válida no cabeçalho.';
    public static string $JWT_WITHOUT_KID = 'O JWT não possui uma propriedade kid válida no cabeçalho.';
    public static string $JWT_WITHOUT_TYP = 'O JWT não possui uma propriedade typ válida no cabeçalho.';
    public static string $REQUIRED_USER_FOR_LOGOUT = 'O usuário precisa estar autenticado para fazer logout.';
}