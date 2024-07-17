package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.oauth2.OAuth2ErrorException;
import com.contentgrid.tokenmonger.oauth2.grants.TokenExchangeGrantRequest;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

public class NoScopeGrantRequestValidator<C> implements GrantRequestValidator<TokenExchangeGrantRequest, C> {

    @Override
    public void validate(TokenExchangeGrantRequest grantRequest, C context) {
        if(!grantRequest.getScope().isEmpty()) {
            throw new OAuth2ErrorException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), "The 'scope' parameter must be absent");
        }
    }
}
