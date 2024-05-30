package com.contentgrid.tokenmonger.token;

import java.util.Map;
import java.util.function.BiPredicate;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;

@RequiredArgsConstructor
public class ClaimsFromOriginalToken implements OAuth2TokenCustomizer<JwtEncodingContext> {
    private final BiPredicate<String, Object> claimFilter;

    @Override
    public void customize(JwtEncodingContext context) {
        var originalClaims = originalTokenClaims(context.getPrincipal());

        originalClaims.forEach((name, value) -> {
            if(claimFilter.test(name, value)) {
                context.getClaims().claim(name, value);
            }
        });
    }

    private Map<String, Object> originalTokenClaims(Object principal) {
        if(principal instanceof OAuth2TokenExchangeCompositeAuthenticationToken compositeAuthenticationToken) {
            principal = compositeAuthenticationToken.getSubject();
        }
        if(principal instanceof AbstractOAuth2TokenAuthenticationToken<?> oauth2AuthenticationToken) {
            return oauth2AuthenticationToken.getTokenAttributes();
        }
        throw new IllegalArgumentException("Unsupported principal of type %s".formatted(principal.getClass()));
    }

}
