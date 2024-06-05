package com.contentgrid.tokenmonger.configuration;

import com.contentgrid.tokenmonger.configuration.EndpointConfiguration.Endpoint;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.Map;
import java.util.function.Consumer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata.Builder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationServerMetadataEndpointFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

public class AuthorizationServerMetadataEndpointConfigurer extends AbstractHttpConfigurer<AuthorizationServerMetadataEndpointConfigurer, HttpSecurity> {
    private static final URL NULL_URL;

    static {
        try {
            NULL_URL = new URL(null, "about:blank", new URLStreamHandler() {
                @Override
                protected URLConnection openConnection(URL u) throws IOException {
                    throw new IOException("about:blank can not be opened");
                }
            });
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private Consumer<Builder> authorizationServerMetadataCustomizer = builder -> {
        builder.claims(Map::clear);
        builder.claim(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT, NULL_URL);
        builder.claim(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT, NULL_URL);
    };

    public AuthorizationServerMetadataEndpointConfigurer authorizationServerMetadataCustomizer(Consumer<Builder> customizer) {
        this.authorizationServerMetadataCustomizer = this.authorizationServerMetadataCustomizer.andThen(customizer);
        return this;
    }

    public AuthorizationServerMetadataEndpointConfigurer endpoints(EndpointConfiguration endpoints) {
        authorizationServerMetadataCustomizer(authorizationServerMetadata -> {
            if(endpoints.issuer() != null) {
                authorizationServerMetadata.issuer(endpoints.issuer().toString());
            }

            mapEndpointUri(endpoints.getAuthorizationEndpoint(), authorizationServerMetadata::authorizationEndpoint);
            mapEndpointUri(endpoints.getJwkSetEndpoint(), authorizationServerMetadata::jwkSetUrl);
            mapEndpointUri(endpoints.getTokenEndpoint(), authorizationServerMetadata::tokenEndpoint);
            mapEndpointUri(endpoints.getTokenIntrospectionEndpoint(), authorizationServerMetadata::tokenIntrospectionEndpoint);
            mapEndpointUri(endpoints.getTokenRevocationEndpoint(), authorizationServerMetadata::tokenRevocationEndpoint);
        });

        return this;
    }

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        OAuth2AuthorizationServerMetadataEndpointFilter authorizationServerMetadataEndpointFilter =
                new OAuth2AuthorizationServerMetadataEndpointFilter();
        authorizationServerMetadataEndpointFilter.setAuthorizationServerMetadataCustomizer(this.authorizationServerMetadataCustomizer);
        httpSecurity.addFilterBefore(postProcess(authorizationServerMetadataEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);
    }

    private static void mapEndpointUri(Endpoint endpoint, Consumer<String> metadataSetter) {
        endpoint.getUri().map(URI::toASCIIString).ifPresent(metadataSetter);
    }
}
