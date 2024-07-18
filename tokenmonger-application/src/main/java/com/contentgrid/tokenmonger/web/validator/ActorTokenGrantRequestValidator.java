package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.oauth2.grants.TokenExchangeGrantRequest;
import com.contentgrid.tokenmonger.oauth2.token.decoder.TokenDecoder;
import com.contentgrid.tokenmonger.web.validator.ActorTokenGrantRequestValidator.ActorTokenInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;

@RequiredArgsConstructor
public class ActorTokenGrantRequestValidator<C extends ActorTokenInfo> implements GrantRequestValidator<TokenExchangeGrantRequest, C> {
    private final TokenDecoder<Jwt> tokenDecoder;

    @Override
    public void validate(TokenExchangeGrantRequest grantRequest, C context) {
        context.setActorToken(tokenDecoder.decode(grantRequest.getActorToken()));
    }

    public interface ActorTokenInfo {
        void setActorToken(Jwt actorToken);
        Jwt getActorToken();
    }

}
