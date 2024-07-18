package com.contentgrid.tokenmonger.oauth2.grants;

import java.net.URI;
import java.util.List;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@Builder(access = AccessLevel.PACKAGE)
public class ContentgridExtensionTokenGrantRequest implements GrantRequest, GrantRequest.HasScope {
    @NonNull
    GrantType grantType;

    @NonNull
    URI resource;

    List<String> scope;
}
