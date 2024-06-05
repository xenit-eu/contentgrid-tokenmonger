package com.contentgrid.tokenmonger.authentication;

import static com.contentgrid.tokenmonger.authentication.UserToExtensionTokenExchangeAuthenticationConverter.ACCESS_TOKEN_REQUEST_ERROR_URI;

import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtension;
import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtensionRepository;
import java.security.Principal;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

@RequiredArgsConstructor
public class UserToExtensionTokenExchangeAuthenticationProvider implements AuthenticationProvider {

    private static final String INVALID_TARGET_ERROR_URI = "https://www.rfc-editor.org/rfc/rfc8707.html#section-2";
    private static final String INVALID_TARGET = "invalid_target";

    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final RegisteredExtensionRepository registeredExtensionRepository;
    private final RegisteredClientRepository registeredClientRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var tokenExchangeAuthentication = (UserToExtensionTokenExchangeAuthenticationToken) authentication;

        // Lookup registered client based on resource URIs
        RegisteredClient registeredClient = null;
        if(tokenExchangeAuthentication.getResources().isEmpty()) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "OAuth 2.0 parameter 'resource' is required", ACCESS_TOKEN_REQUEST_ERROR_URI)
            );
        }
        for (String resource : tokenExchangeAuthentication.getResources()) {
            var resourceClient = findRegisteredClientByResourceUri(resource);
            if (registeredClient != null && !Objects.equals(registeredClient.getClientId(), resourceClient.getClientId())) {
                throw new OAuth2AuthenticationException(
                        new OAuth2Error(INVALID_TARGET, "Resource parameters are registered with different clients", INVALID_TARGET_ERROR_URI)
                );
            }
            registeredClient = resourceClient;
        }

        Assert.notNull(registeredClient, "Registered client should be found at this point");

        if(!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantExtensions.CONTENTGRID_EXTENSION_TOKEN_GRANT_TYPE)) {
            throw  new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, "Client is not authorized for grant type "+AuthorizationGrantExtensions.CONTENTGRID_EXTENSION_TOKEN_GRANT_TYPE, "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2")
            );
        }

        var context = DefaultOAuth2TokenContext.builder()
                .principal(tokenExchangeAuthentication.getPrincipal())
                .registeredClient(registeredClient)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizationGrantType(AuthorizationGrantExtensions.CONTENTGRID_EXTENSION_TOKEN_GRANT_TYPE)
                .build();

        var generatedAccessToken = tokenGenerator.generate(context);
        if (generatedAccessToken == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", "about:blank"));
        }

        var oauth2AccessToken = new OAuth2AccessToken(
                TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt()
        );

        var accessTokenFormat = context.getRegisteredClient().getTokenSettings().getAccessTokenFormat();

        var authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(tokenExchangeAuthentication.getName())
                .attribute(Principal.class.getName(), tokenExchangeAuthentication.getPrincipal())
                .authorizationGrantType(AuthorizationGrantExtensions.CONTENTGRID_EXTENSION_TOKEN_GRANT_TYPE)
                .token(oauth2AccessToken, metadata -> {
                    if (generatedAccessToken instanceof ClaimAccessor claimAccessor) {
                        metadata.put(Token.CLAIMS_METADATA_NAME, claimAccessor.getClaims());
                    }
                    metadata.put(Token.INVALIDATED_METADATA_NAME, false);
                    metadata.put(OAuth2TokenFormat.class.getName(), accessTokenFormat.getValue());
                })
                .build();

        authorizationService.save(authorization);

        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient,
                new OAuth2ClientAuthenticationToken(registeredClient, ClientAuthenticationMethod.NONE, null),
                oauth2AccessToken
        );

    }

    private RegisteredClient findRegisteredClientByResourceUri(String resourceUri) {
        var extension = registeredExtensionRepository.findByResourceUri(resourceUri);
        if(extension.isEmpty()) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(INVALID_TARGET, "Resource '%s' is not registered with any extension".formatted(resourceUri), INVALID_TARGET_ERROR_URI)
            );
        }

        for (String clientId : extension.get().getClientIds()) {
            var registeredClient = registeredClientRepository.findByClientId(clientId);
            if(registeredClient == null) {
                continue;
            }

            var clientSecretExpiry = Optional.ofNullable(registeredClient.getClientSecretExpiresAt()).orElse(Instant.MAX);
            // Client is expired, can no longer be used for authentication
            if(clientSecretExpiry.isBefore(Instant.now())) {
                continue;
            }

            return registeredClient;
        }

        throw new OAuth2AuthenticationException(
                new OAuth2Error(INVALID_TARGET, "Resource '%s' is not registered with any active client".formatted(resourceUri), INVALID_TARGET_ERROR_URI)
        );

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UserToExtensionTokenExchangeAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
