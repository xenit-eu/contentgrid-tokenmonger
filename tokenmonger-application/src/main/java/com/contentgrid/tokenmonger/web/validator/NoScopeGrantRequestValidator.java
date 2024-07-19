package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.oauth2.OAuth2ErrorException;
import com.contentgrid.tokenmonger.oauth2.grants.GrantRequest;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

public class NoScopeGrantRequestValidator<C> implements GrantRequestValidator<GrantRequest.HasScope, C> {

    @Override
    public String getDescription() {
        return "The 'scope' parameter must be absent";
    }

    @Override
    public void validate(GrantRequest.HasScope grantRequest, C context) {
        if(!grantRequest.getScope().isEmpty()) {
            throw new OAuth2ErrorException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), getDescription());
        }
    }
}
