package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.oauth2.error.OAuth2ErrorBuilder;
import com.contentgrid.tokenmonger.oauth2.grants.TokenExchangeGrantRequest;

public class NoAudienceGrantRequestValidator<C> implements GrantRequestValidator<TokenExchangeGrantRequest, C> {

    @Override
    public String getDescription() {
        return "The 'audience' parameter must be absent";
    }

    @Override
    public void validate(TokenExchangeGrantRequest grantRequest, C context) {
        if(!grantRequest.getAudience().isEmpty()) {
            throw OAuth2ErrorBuilder.invalidRequest()
                    .parameter("audience")
                    .mustBeAbsent()
                    .buildException();
        }
    }
}
