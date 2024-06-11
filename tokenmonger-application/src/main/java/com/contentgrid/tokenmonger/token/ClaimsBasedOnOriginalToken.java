package com.contentgrid.tokenmonger.token;

import java.util.function.BiConsumer;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.jwt.JwtClaimsSet.Builder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;

@RequiredArgsConstructor
public class ClaimsBasedOnOriginalToken implements OAuth2TokenCustomizer<JwtEncodingContext> {
    private final BiConsumer<ClaimAccessor, Builder> configurer;

    @Override
    public void customize(JwtEncodingContext context) {
        configurer.accept(originalTokenClaims(context.getPrincipal()), context.getClaims());
    }

    private ClaimAccessor originalTokenClaims(Object principal) {
        if(principal instanceof OAuth2TokenExchangeCompositeAuthenticationToken compositeAuthenticationToken) {
            principal = compositeAuthenticationToken.getSubject();
        }
        if(principal instanceof AbstractOAuth2TokenAuthenticationToken<?> oauth2AuthenticationToken) {
            return oauth2AuthenticationToken::getTokenAttributes;
        }
        throw new IllegalArgumentException("Unsupported principal of type %s".formatted(principal.getClass()));
    }
}
