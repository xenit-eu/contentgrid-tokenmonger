package com.contentgrid.tokenmonger.token;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeActor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

public class ActorsFromAuthentication implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        if(context.getPrincipal() instanceof OAuth2TokenExchangeCompositeAuthenticationToken compositeAuthenticationToken) {
            chainActors(compositeAuthenticationToken.getActors()).ifPresent(actorsClaim -> {
                context.getClaims().claim("act", actorsClaim);
            });
        }
    }

    private static Optional<Map<String, Object>> chainActors(List<OAuth2TokenExchangeActor> actors) {
        if(actors.isEmpty()) {
            return Optional.empty();
        }
        var actor = actors.get(0);

        Map<String, Object> actorClaims = new LinkedHashMap<>(); // linked hashmap to keep the order of the attributes
        actorClaims.put(JwtClaimNames.ISS, actor.getIssuer());
        actorClaims.put(JwtClaimNames.SUB, actor.getSubject());

        chainActors(actors.subList(1, actors.size())).ifPresent(nestedActorClaims -> {
            actorClaims.put("act", nestedActorClaims);
        });

        return Optional.of(actorClaims);
    }
}
