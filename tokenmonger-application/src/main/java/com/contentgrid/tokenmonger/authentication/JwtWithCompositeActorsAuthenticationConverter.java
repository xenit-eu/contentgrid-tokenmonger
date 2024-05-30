package com.contentgrid.tokenmonger.authentication;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeActor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;

@RequiredArgsConstructor
public class JwtWithCompositeActorsAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    private final Converter<Jwt, AbstractAuthenticationToken> subjectConverter;

    @Override
    public AbstractAuthenticationToken convert(Jwt source) {
        var subject = subjectConverter.convert(source);
        if(subject == null) {
            return null;
        }

        if (!source.hasClaim("act")) {
            return subject;
        }

        return new OAuth2TokenExchangeCompositeAuthenticationToken(
                subject,
                extractNestedActors(source.getClaimAsMap("act"))
        );
    }

    private List<OAuth2TokenExchangeActor> extractNestedActors(Map<String, Object> claims) {
        List<OAuth2TokenExchangeActor> actors = new ArrayList<>();
        do {
            actors.add(new OAuth2TokenExchangeActor(claims));

            claims = new NestedClaimAccessor(claims).getClaimAsMap("act");
        } while(claims != null);

        return actors;
    }

    @Value
    private static class NestedClaimAccessor implements ClaimAccessor {
        Map<String, Object> claims;
    }
}
