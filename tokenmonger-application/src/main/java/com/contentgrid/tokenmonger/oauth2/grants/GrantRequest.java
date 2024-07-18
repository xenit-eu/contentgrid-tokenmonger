package com.contentgrid.tokenmonger.oauth2.grants;

import java.net.URI;
import java.util.List;

public interface GrantRequest {
    GrantType getGrantType();

    interface HasScope extends GrantRequest {
        List<String> getScope();
    }

    interface HasResource extends GrantRequest {
        List<URI> getResource();
    }
}
