package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.oauth2.error.OAuth2ErrorBuilder;
import com.contentgrid.tokenmonger.oauth2.grants.TokenExchangeGrantRequest;

public class NoActorTokenExchangeGrantRequestValidator<C> implements GrantRequestValidator<TokenExchangeGrantRequest, C> {

    @Override
    public String getDescription() {
        return "Actor token must be absent";
    }

    @Override
    public void validate(TokenExchangeGrantRequest grantRequest, C context) {
        if(grantRequest.getActorToken() != null) {
            throw OAuth2ErrorBuilder.invalidRequest()
                    .parameter("actor_token")
                    .mustBeAbsent()
                    .buildException();
        }
    }
}
