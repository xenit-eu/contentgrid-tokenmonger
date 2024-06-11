package com.contentgrid.tokenmonger.authentication;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;

public class UserToExtensionTokenExchangeAuthenticationConverter implements AuthenticationConverter {
    static final String ACCESS_TOKEN_REQUEST_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    @Override
    public Authentication convert(HttpServletRequest request) {
        // grant_type (REQUIRED)
        if(!Objects.equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE),
                AuthorizationGrantExtensions.CONTENTGRID_EXTENSION_TOKEN_GRANT_TYPE.getValue())) {
            return null;
        }

        // resource (REQUIRED)
        var resources = request.getParameterValues(OAuth2ParameterNames.RESOURCE);
        if(resources == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "OAuth 2.0 Parameter: "+OAuth2ParameterNames.RESOURCE, ACCESS_TOKEN_REQUEST_ERROR_URI)
            );
        }
        for (String resource : resources) {
            if(!isValidUri(resource)) {
                throw new OAuth2AuthenticationException(
                        new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "OAuth 2.0 Parameter: "+OAuth2ParameterNames.RESOURCE, ACCESS_TOKEN_REQUEST_ERROR_URI)
                );
            }
        }


        return new UserToExtensionTokenExchangeAuthenticationToken(
                SecurityContextHolder.getContext().getAuthentication(),
                new HashSet<>(Arrays.asList(resources))
        );

    }

    private boolean isValidUri(String resource) {
        try {
            var uri = new URI(resource);
            return uri.isAbsolute() && uri.getFragment() == null;
        } catch (URISyntaxException e) {
            return false;
        }
    }
}
