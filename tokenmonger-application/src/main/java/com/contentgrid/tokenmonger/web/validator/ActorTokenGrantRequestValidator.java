package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.oauth2.error.OAuth2ErrorBuilder;
import com.contentgrid.tokenmonger.oauth2.grants.TokenExchangeGrantRequest;
import com.contentgrid.tokenmonger.oauth2.token.decoder.TokenDecoder;
import com.contentgrid.tokenmonger.web.validator.ActorTokenGrantRequestValidator.ActorTokenInfo;
import com.contentgrid.tokenmonger.web.validator.SubjectTokenGrantRequestValidator.SubjectTokenInfo;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;

@RequiredArgsConstructor
public class ActorTokenGrantRequestValidator<C extends ActorTokenInfo> implements GrantRequestValidator<TokenExchangeGrantRequest, C> {
    private final TokenDecoder<Jwt> tokenDecoder;

    @Override
    public String getDescription() {
        return "Actor token is required and must be authorized by the subject token.";
    }

    @Override
    public void validate(TokenExchangeGrantRequest grantRequest, C context) {
        if(grantRequest.getActorToken() == null) {
            throw OAuth2ErrorBuilder.invalidRequest()
                    .parameter("actor_token")
                    .isRequired()
                    .uri("https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1")
                    .buildException();
        }
        var actorToken = tokenDecoder.decode(grantRequest.getActorToken(), OAuth2ErrorBuilder.invalidRequest().parameter("actor_token"));

        var subjectAllowedActor = context.getSubjectToken().getClaimAsMap("may_act");

        if(!isActorAllowed(actorToken, subjectAllowedActor)) {
            throw OAuth2ErrorBuilder.invalidRequest()
                    .parameter("actor_token")
                    .description("is not allowed to act on behalf of the subject")
                    .uri("https://www.rfc-editor.org/rfc/rfc8693.html#section-4.4")
                    .buildException();
        }

        context.setActorToken(actorToken);
    }

    private static boolean isActorAllowed(Jwt actorToken, Map<String, Object> mayActClaims) {
        if(mayActClaims == null) {
            return false;
        }

        for (Entry<String, Object> mayActClaim : mayActClaims.entrySet()) {
            var actorTokenClaim = actorToken.getClaimAsString(mayActClaim.getKey());
            if(!Objects.equals(mayActClaim.getValue(), actorTokenClaim)) {
                return false;
            }
        }
        return true;
    }

    public interface ActorTokenInfo extends SubjectTokenInfo {
        void setActorToken(Jwt actorToken);
        Jwt getActorToken();
    }

}
