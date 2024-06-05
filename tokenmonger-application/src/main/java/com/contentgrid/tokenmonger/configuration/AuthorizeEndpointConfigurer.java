package com.contentgrid.tokenmonger.configuration;

import com.contentgrid.tokenmonger.configuration.EndpointConfiguration.Endpoint;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationConsentAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Accessors(fluent = true, chain = true)
public class AuthorizeEndpointConfigurer extends AbstractHttpConfigurer<TokenEndpointConfigurer, HttpSecurity> {
    @Setter
    private Endpoint authorizeEndpoint;

    private ConfigurationFunction<AuthenticationConverter> authorizationRequestConverters = new ConfigurationFunction<>(this::postProcess);
    private ConfigurationFunction<AuthenticationProvider> authenticationProviders = new ConfigurationFunction<>(this::postProcess);

    @Setter
    private AuthenticationSuccessHandler authorizationResponseHandler;

    @Setter
    private AuthenticationFailureHandler errorResponseHandler;

    private String consentPage;

    @Setter
    private SessionAuthenticationStrategy sessionAuthenticationStrategy;


    public AuthorizeEndpointConfigurer authenticationProviders(@NonNull Consumer<List<AuthenticationProvider>> configurer) {
        authenticationProviders.add(configurer);
        return this;
    }

    public AuthorizeEndpointConfigurer authenticationProvider(@NonNull AuthenticationProvider authenticationProvider) {
        authenticationProviders.item(authenticationProvider);
        return this;
    }

    public AuthorizeEndpointConfigurer authorizationRequestConverters(@NonNull Consumer<List<AuthenticationConverter>> configurer) {
        authorizationRequestConverters.add(configurer);
        return this;
    }

    public AuthorizeEndpointConfigurer authorizationRequestConverter(@NonNull AuthenticationConverter authorizationRequestConverter) {
        authorizationRequestConverters.item(authorizationRequestConverter);
        return this;
    }

    public AuthorizeEndpointConfigurer withAuthorizationCode() {
        return withAuthorizationCode(authenticationContext -> {});
    }

    public AuthorizeEndpointConfigurer withAuthorizationCode(Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authorizationCodeRequestAuthenticationValidator) {
        authenticationProviders.supply(httpSecurity -> {
            var authorizationCodeRequestAuthenticationProvider = new OAuth2AuthorizationCodeRequestAuthenticationProvider(
                    ConfigurerUtils.getRegisteredClientRepository(httpSecurity),
                    ConfigurerUtils.getAuthorizationService(httpSecurity),
                    ConfigurerUtils.getAuthorizationConsentService(httpSecurity)
            );

            authorizationCodeRequestAuthenticationProvider.setAuthenticationValidator(
                    new OAuth2AuthorizationCodeRequestAuthenticationValidator()
                            .andThen(authorizationCodeRequestAuthenticationValidator)
            );

            return authorizationCodeRequestAuthenticationProvider;
        });

        authorizationRequestConverters.item(new OAuth2AuthorizationCodeRequestAuthenticationConverter());
        return this;
    }

    public AuthorizeEndpointConfigurer withConsent(String consentPage) {
        authenticationProviders.supply(httpSecurity -> new OAuth2AuthorizationConsentAuthenticationProvider(
                ConfigurerUtils.getRegisteredClientRepository(httpSecurity),
                ConfigurerUtils.getAuthorizationService(httpSecurity),
                ConfigurerUtils.getAuthorizationConsentService(httpSecurity)
        ));

        authorizationRequestConverters.item(new OAuth2AuthorizationConsentAuthenticationConverter());

        this.consentPage = consentPage;
        return this;
    }

    @Override
    public void init(HttpSecurity httpSecurity) throws Exception {
        this.authenticationProviders.apply(httpSecurity)
                .forEach(httpSecurity::authenticationProvider);
    }

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        var authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);

        var authorizationEndpointFilter = new OAuth2AuthorizationEndpointFilter(
                authenticationManager,
                authorizeEndpoint.getPath()
        );

        authorizationEndpointFilter.setAuthenticationConverter(new DelegatingAuthenticationConverter(this.authorizationRequestConverters.apply(httpSecurity)));

        if(authorizationResponseHandler != null) {
            authorizationEndpointFilter.setAuthenticationSuccessHandler(authorizationResponseHandler);
        }

        if(errorResponseHandler != null) {
            authorizationEndpointFilter.setAuthenticationFailureHandler(errorResponseHandler);
        }

        if(consentPage != null)  {
            authorizationEndpointFilter.setConsentPage(consentPage);
        }

        if(sessionAuthenticationStrategy != null) {
            authorizationEndpointFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        }

        // This is different from spring-authorization-server configuration:
        // we need the authorization endpoint after all potential authentication filters, instead of before
        // because we receive an authorization header with a bearer token that needs to be authenticated at each request
        // instead of the authentication object already being loaded from the session in an earlier filter
        httpSecurity.addFilterAfter(postProcess(authorizationEndpointFilter), AnonymousAuthenticationFilter.class);
    }
}
