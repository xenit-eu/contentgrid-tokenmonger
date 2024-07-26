package com.contentgrid.tokenmonger.oauth2.grants;

import java.net.URI;
import java.util.List;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@Builder(access = AccessLevel.PACKAGE)
public class ContentgridExtensionTokenGrantRequest implements GrantRequest, GrantRequest.HasScope, GrantRequest.HasResource {
    @NonNull
    GrantType grantType;

    @NonNull
    List<URI> resource;

    List<String> scope;
}
