package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.oauth2.error.OAuth2ErrorBuilder;
import com.contentgrid.tokenmonger.oauth2.grants.GrantRequest;

public class NoScopeGrantRequestValidator<C> implements GrantRequestValidator<GrantRequest.HasScope, C> {

    @Override
    public String getDescription() {
        return "The 'scope' parameter must be absent";
    }

    @Override
    public void validate(GrantRequest.HasScope grantRequest, C context) {
        if(!grantRequest.getScope().isEmpty()) {
            throw OAuth2ErrorBuilder.invalidRequest()
                    .parameter("scope")
                    .mustBeAbsent()
                    .buildException();
        }
    }
}
