package com.contentgrid.tokenmonger.oauth2.grants;

import java.util.List;

public interface GrantRequest {
    GrantType getGrantType();

    interface HasScope extends GrantRequest {
        List<String> getScope();
    }
}
