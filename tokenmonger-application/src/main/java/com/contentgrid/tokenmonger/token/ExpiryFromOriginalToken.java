package com.contentgrid.tokenmonger.token;

import java.time.Instant;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtClaimsSet.Builder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;

public class ExpiryFromOriginalToken implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        var originalTokenExpiry = originalTokenExpiry(context.getPrincipal());
        if(originalTokenExpiry != null) {
            var thisTokenExpiry = context.getClaims().build().getExpiresAt();
            if(thisTokenExpiry.isAfter(originalTokenExpiry)) {
                context.getClaims().expiresAt(originalTokenExpiry);
            }
        }
    }

    private Instant originalTokenExpiry(Object principal) {
        if(principal instanceof OAuth2TokenExchangeCompositeAuthenticationToken compositeAuthenticationToken) {
            principal = compositeAuthenticationToken.getSubject();
        }
        if(principal instanceof AbstractOAuth2TokenAuthenticationToken<?> oauth2AuthenticationToken) {
            return oauth2AuthenticationToken.getToken().getExpiresAt();
        }
        throw new IllegalArgumentException("Unsupported principal of type %s".formatted(principal.getClass()));
    }
}
