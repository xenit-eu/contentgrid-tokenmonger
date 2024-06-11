# ContentGrid Tokenmonger

Tokenmonger manages JWT authentication tokens for ContentGrid extensions.

It creates the following types of tokens:

* External authentication: Authenticates a ContentGrid user to a specific ContentGrid extension
* ContentGrid extension service account: Authenticates a ContentGrid extension itself
* Delegated authentication: Authenticates a ContentGrid extension acting on behalf of a ContentGrid user to a ContentGrid application

## Usage

### Obtaining tokens

Tokenmonger follows the OAuth 2.0 specification for issuing and exchanging authentication tokens.

A user is responsible for obtaining a user token from an OAuth/OpenID Connect authentication provider.
Tokenmonger does not authenticate users or issue tokens that directly identify users.

Token issuance typically happens in the order described here, but sometimes some steps may be skipped.

1. Authenticate a user to a ContentGrid extension
   There are 2 ways to authenticate to a ContentGrid extension: pre-emptive authentication with a bearer token or redirect-based authentication using the OAuth authorization_code flow
   This initial exchange happens in the same context as in which the user is authenticated (user token is not sent to an additional origin)
   1. pre-emptive authentication
      Make a POST request to `<app domain>/.contentgrid/authentication/external/token`, using `grant_type=https://contentgrid.cloud/oauth2/grant/extension-token` 
      and the `resource` parameter set to the external resource(s) you want to request. Send the user token in the `Authorization` header.
      You will receive back a standard OAuth token response with an `access_token` (no refresh tokens are issued)
      This newly-issued access token is now sent to the extension as a bearer token in the `Authorization` header.
   2. redirect-based authentication
      Make a request to the external resource. The external resource is expected to perform an OAuth 2.0 authorization code grant flow.
      The authorize endpoint is at `<app domain>/.contentgrid/authentication/external/authorize`, the token endpoint is at `<tokenmonger domain>/authentication/external/token`.
      The extension obtains an access token (the same as in pre-emptive authentication) and use that to authenticate the user.
2. Authenticate ContentGrid extension (service account)
   A ContentGrid extension can obtain an authentication token to authenticate itself **to tokenmonger** by using the OAuth 2.0 client credentials grant flow.
   The token endpoint is at `<tokenmonger domain>/authentication/system/token`
   You will receive back a standard OAuth token response with an `access_token` 
3. Authenticate a ContentGrid extension to a ContentGrid application on behalf of a user
   A ContentGrid extension can obtain a delegated authentication token to make requests to a ContentGrid application on behalf of the user that is using the extension.
   This makes use of OAuth 2.0 Token Exchange, with `subject_token` set to the users' external authentication token from step 1 and the `actor_token` set to the ContentGrid extension service account token.
   The token endpoint is at `<tokenmonger daomain>/authentication/delegated/token`
   You will receive back a standard OAuth token response with an `access_token` (no refresh tokens are issued)
   To perform the token exchange, the ContentGrid extension also needs to identify itself with it's client credentials.

## Configuration

### JWT issuers

For every kind of token, Tokenmonger has a different JWT issuer and separate signing keys.

The issuer URI and the locations on the filesystem where signing keys can be found are configured separately for every token type.
Signing keys can be provided in PEM or JWK format, with one key per file.

Both active and retired signing keys can be provided. Only active keys are used for signing tokens.
Retired keys are served on the JWK Set endpoint so already issued tokens can still be verified.
Signing keys are regularly (but not immediately) reloaded from filesystem.

| Property                                                         | Type             | Description                                                                        |
|:-----------------------------------------------------------------|------------------|------------------------------------------------------------------------------------|
| `contentgrid.tokenmonger.user-to-extension.issuer`               | URI              | Issuer for the external authentication token                                       |
| `contentgrid.tokenmonger.user-to-extension.jwk-set-uri`          | URI              | URI of the JWK Set to verify ContentGrid user tokens (not issued by this component |
| `contentgrid.tokenmonger.user-to-extension.active-signing-keys`  | location pattern | File pattern to load active signing keys from                                      |
| `contentgrid.tokenmonger.user-to-extension.retired-signing-keys` | location pattern | File pattern to load retired signing keys from                                     |
| `contentgrid.tokenmonger.extension-to-app.issuer`                | URI              | Issuer for the delegated authentication token                                      |
| `contentgrid.tokenmonger.extension-to-app.active-signing-keys`   | location pattern | File pattern to load active signing keys from                                      |
| `contentgrid.tokenmonger.extension-to-app.retired-signing-keys`  | location pattern | File pattern to load retired signing keys from                                     |
| `contentgrid.tokenmonger.extension.issuer`                       | URI              | Issuer for the extension service account token                                     |
| `contentgrid.tokenmonger.extension.active-signing-keys`          | location pattern | File pattern to load active signing keys from                                      |
| `contentgrid.tokenmonger.extension.retired-signing-keys`         | location pattern | File pattern to load retired signing keys from                                     |

### OAuth clients for ContentGrid extensions

Tokenmonger only has OAuth clients for ContentGrid extensions.

Use [the standard boot configuration for spring security authorization server](https://docs.spring.io/spring-boot/reference/web/spring-security.html#web.security.oauth2.authorization-server) to register clients.

Only the client authentication methods `client_secret_basic` and `client_secret_post` are supported, and are both using a client secret for authenticating.

Following authorization grant types are supported:

 * `authorization_code` & `https://contentgrid.cloud/oauth2/grant/extension-token`: for obtaining an external authentication token (via OAuth authorization_code flow or via token exchange)
 * `client_credentials`: for obtaining a ContentGrid extension service account token
 * `urn:ietf:params:oauth:grant-type:token-exchange`: for obtaining a delegated authentication token

Authorization grant types can be omitted when a certain functionality is not necessary.

To make a client usable for a ContentGrid extension, it also needs to be registered under `contentgrid.tokenmonger.extension.registration`:

| Property                                                         | Type            | Description                                                                                                                         |
|------------------------------------------------------------------|-----------------|-------------------------------------------------------------------------------------------------------------------------------------|
| `contentgrid.tokenmonger.extension.registration.*.extension-id`  | string          | Unique identifier of the extension. This value is used as `sub` in extension service account tokens.                                |
| `contentgrid.tokenmonger.extension.registration.*.client-ids`    | list of strings | List of OAuth client IDs that belong to this extension. A Client ID can only belong to one extension.                               |
| `contentgrid.tokenmonger.extension.registration.*.resource-uris` | list of strings | List of resource URIs used by the extension. Will be used to resolve the extension when obtaining an external authentication token. |






