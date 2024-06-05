package com.contentgrid.tokenmonger.configuration;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.NonNull;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

public class ServicesConfigurer extends AbstractHttpConfigurer<ServicesConfigurer, HttpSecurity> {

    public ServicesConfigurer registeredClientRepository(@NonNull RegisteredClientRepository registeredClientRepository) {
        getBuilder().setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
        return this;
    }

    public ServicesConfigurer authorizationService(@NonNull OAuth2AuthorizationService authorizationService) {
        getBuilder().setSharedObject(OAuth2AuthorizationService.class, authorizationService);
        return this;
    }

    public ServicesConfigurer authorizationConsentService(@NonNull OAuth2AuthorizationConsentService authorizationConsentService) {
        getBuilder().setSharedObject(OAuth2AuthorizationConsentService.class, authorizationConsentService);
        return this;
    }

    public ServicesConfigurer tokenGenerator(@NonNull OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        getBuilder().setSharedObject(OAuth2TokenGenerator.class, tokenGenerator);
        return this;
    }

    public ServicesConfigurer jwkSource(@NonNull JWKSource<SecurityContext> jwkSource) {
        getBuilder().setSharedObject(JWKSource.class, jwkSource);
        return this;
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        super.configure(builder);
    }
}
