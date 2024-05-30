package com.contentgrid.tokenmonger.token;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

@RequiredArgsConstructor
public class RequireActorOAuth2TokenGenerator<T extends OAuth2Token> implements OAuth2TokenGenerator<T> {
    private final OAuth2TokenGenerator<T> delegate;

    @Override
    public T generate(OAuth2TokenContext context) {
        if(context.getPrincipal() instanceof OAuth2TokenExchangeCompositeAuthenticationToken) {
            return delegate.generate(context);
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }
}
