package com.contentgrid.tokenmonger.configuration;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.authorization.web.NimbusJwkSetEndpointFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

@Accessors(fluent = true, chain = true)
public class JwkSetEndpointConfigurer extends AbstractHttpConfigurer<JwkSetEndpointConfigurer, HttpSecurity> {

    @Setter
    private EndpointConfiguration.Endpoint jwkSetEndpoint;

    @Override
    public void init(HttpSecurity builder) throws Exception {
        super.init(builder);
    }

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        JWKSource<SecurityContext> jwkSource = ConfigurerUtils.getJwkSource(httpSecurity);
        if (jwkSource != null) {
            NimbusJwkSetEndpointFilter jwkSetEndpointFilter = new NimbusJwkSetEndpointFilter(
                    jwkSource, jwkSetEndpoint.getPath());
            httpSecurity.addFilterBefore(postProcess(jwkSetEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);
        }
    }
}
