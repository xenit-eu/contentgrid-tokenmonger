package com.contentgrid.tokenmonger.authentication;

import java.util.Collections;
import java.util.Set;
import lombok.Getter;
import lombok.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;

public class UserToExtensionTokenExchangeAuthenticationToken extends AbstractAuthenticationToken {
    @NonNull
    private final AbstractOAuth2TokenAuthenticationToken<?> userPrincipal;

    @NonNull
    @Getter
    private final Set<String> resources;

    public UserToExtensionTokenExchangeAuthenticationToken(AbstractOAuth2TokenAuthenticationToken<?> principal, Set<String> resources) {
        super(Collections.emptyList());
        this.userPrincipal = principal;
        this.resources = resources;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public AbstractOAuth2TokenAuthenticationToken<?> getPrincipal() {
        return userPrincipal;
    }
}
