package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.oauth2.OAuth2ErrorException;
import com.contentgrid.tokenmonger.oauth2.grants.TokenExchangeGrantRequest;
import com.contentgrid.tokenmonger.oauth2.token.decoder.TokenDecoder;
import com.contentgrid.tokenmonger.web.validator.ActorTokenGrantRequestValidator.ActorTokenInfo;
import com.contentgrid.tokenmonger.web.validator.SubjectTokenGrantRequestValidator.SubjectTokenInfo;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;

@RequiredArgsConstructor
public class ActorTokenGrantRequestValidator<C extends ActorTokenInfo> implements GrantRequestValidator<TokenExchangeGrantRequest, C> {
    private final TokenDecoder<Jwt> tokenDecoder;

    @Override
    public void validate(TokenExchangeGrantRequest grantRequest, C context) {
        var actorToken = tokenDecoder.decode(grantRequest.getActorToken());

        var subjectAllowedActor = context.getSubjectToken().getClaimAsMap("may_act");

        if(!isActorAllowed(actorToken, subjectAllowedActor)) {
            throw new OAuth2ErrorException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Actor is not allowed to act on behalf of the subject", "https://www.rfc-editor.org/rfc/rfc8693.html#section-4.4"));
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
