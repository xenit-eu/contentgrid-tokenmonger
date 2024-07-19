package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.oauth2.grants.GrantRequest;

public interface GrantRequestValidator<T extends GrantRequest, C> {
    default String getDescription() {
        return getClass().getSimpleName();
    }
    void validate(T grantRequest, C context);
}
