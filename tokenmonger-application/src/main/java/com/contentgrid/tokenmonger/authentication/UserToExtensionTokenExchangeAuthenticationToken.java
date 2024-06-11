package com.contentgrid.tokenmonger.authentication;

import java.util.Collections;
import java.util.Set;
import lombok.Getter;
import lombok.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;

public class UserToExtensionTokenExchangeAuthenticationToken extends AbstractAuthenticationToken {
    @NonNull
    private final Authentication userPrincipal;

    @NonNull
    @Getter
    private final Set<String> resources;

    public UserToExtensionTokenExchangeAuthenticationToken(Authentication principal, Set<String> resources) {
        super(Collections.emptyList());
        this.userPrincipal = principal;
        this.resources = resources;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Authentication getPrincipal() {
        return userPrincipal;
    }
}
