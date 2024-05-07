package com.contentgrid.tokenmonger.clientregistration;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

public interface RegisteredClientRepository extends
        org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository {

    @Nullable
    RegisteredClient findByResourceUri(String resourceUri);

}
