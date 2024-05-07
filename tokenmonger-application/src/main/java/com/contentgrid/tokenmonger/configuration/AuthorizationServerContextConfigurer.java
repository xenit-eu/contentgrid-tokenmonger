package com.contentgrid.tokenmonger.configuration;

import com.contentgrid.tokenmonger.configuration.EndpointConfiguration.Endpoint;
import com.contentgrid.tokenmonger.filters.AuthorizationServerContextFilter;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;
import lombok.experimental.Accessors;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.context.SecurityContextHolderFilter;

@Accessors(fluent = true, chain = true)
public class AuthorizationServerContextConfigurer extends AbstractHttpConfigurer<AuthorizationServerContextConfigurer, HttpSecurity> {
    private final AuthorizationServerSettings.Builder authorizationServerSettingsBuilder = AuthorizationServerSettings.builder()
            .settings(Map::clear);


    private AuthorizationServerContextConfigurer mapEndpoint(
            Consumer<String> builder,
            Supplier<Endpoint> supplier
    ) {
        var value = supplier.get();
        if(value.getPath() != null) {
            builder.accept(value.getPath());
        }

        return this;
    }

    public AuthorizationServerContextConfigurer issuer(String issuer) {
        authorizationServerSettingsBuilder.issuer(issuer);
        return this;
    }

    public AuthorizationServerContextConfigurer endpoints(EndpointConfiguration endpoints) {
        return mapEndpoint(authorizationServerSettingsBuilder::jwkSetEndpoint, endpoints::getJwkSetEndpoint)
                .mapEndpoint(authorizationServerSettingsBuilder::authorizationEndpoint, endpoints::getAuthorizationEndpoint)
                .mapEndpoint(authorizationServerSettingsBuilder::tokenEndpoint, endpoints::getTokenEndpoint)
                .mapEndpoint(authorizationServerSettingsBuilder::tokenIntrospectionEndpoint, endpoints::getTokenIntrospectionEndpoint)
                .mapEndpoint(authorizationServerSettingsBuilder::tokenRevocationEndpoint, endpoints::getTokenRevocationEndpoint)
                .issuer(endpoints.issuer().toASCIIString());
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        var settings = authorizationServerSettingsBuilder.build();
        http.addFilterAfter(new AuthorizationServerContextFilter(settings), SecurityContextHolderFilter.class);
    }
}
