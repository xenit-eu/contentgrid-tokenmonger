package com.contentgrid.tokenmonger.configuration;

import com.contentgrid.tokenmonger.configuration.EndpointConfiguration.Endpoint;
import com.contentgrid.tokenmonger.filters.DelegatingRequestMatcherFilter;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2TokenExchangeAuthenticationConverter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Accessors(fluent = true, chain = true)
public class TokenEndpointConfigurer extends AbstractHttpConfigurer<TokenEndpointConfigurer, HttpSecurity> {
    @Setter
    private Endpoint tokenEndpoint;

    private ConfigurationFunction<AuthenticationConverter> authenticationConverters = new ConfigurationFunction<>(this::postProcess);
    private ConfigurationFunction<AuthenticationProvider> authenticationProviders = new ConfigurationFunction<>(this::postProcess);

    @Setter
    private AuthenticationSuccessHandler accessTokenResponseHandler;

    @Setter
    private AuthenticationFailureHandler errorResponseHandler;


    public TokenEndpointConfigurer authenticationProviders(@NonNull Consumer<List<AuthenticationProvider>> configurer) {
        authenticationProviders.add(configurer);
        return this;
    }

    public TokenEndpointConfigurer authenticationProvider(@NonNull AuthenticationProvider authenticationProvider) {
        authenticationProviders.item(authenticationProvider);
        return this;
    }

    public TokenEndpointConfigurer authenticationConverters(@NonNull Consumer<List<AuthenticationConverter>> configurer) {
        authenticationConverters.add(configurer);
        return this;
    }

    public TokenEndpointConfigurer authenticationConverter(@NonNull AuthenticationConverter authenticationConverter) {
        authenticationConverters.item(authenticationConverter);
        return this;
    }

    private static <T extends AuthenticationProvider> Function<HttpSecurity, T> supplyAuthenticationProvider(
            BiFunction<OAuth2AuthorizationService, OAuth2TokenGenerator<? extends OAuth2Token>, T> creator,
            BiConsumer<T, HttpSecurity> configurer
    ) {
        return httpSecurity -> {
            var authorizationService = ConfigurerUtils.getAuthorizationService(httpSecurity);
            var tokenGenerator = ConfigurerUtils.getTokenGenerator(httpSecurity);

            var instance = creator.apply(authorizationService, tokenGenerator);
            configurer.accept(instance, httpSecurity);
            return instance;
        };
    }

    private static <T extends AuthenticationProvider> Function<HttpSecurity, T> supplyAuthenticationProvider(
            BiFunction<OAuth2AuthorizationService, OAuth2TokenGenerator<? extends OAuth2Token>, T> creator
    ) {
        return supplyAuthenticationProvider(creator, (authenticationProvider, httpSecurity) -> {

        });
    }

    public TokenEndpointConfigurer withAuthorizationCode() {
        authenticationProviders.supply(supplyAuthenticationProvider(OAuth2AuthorizationCodeAuthenticationProvider::new, (authenticationProvider, httpSecurity) -> {
            var sessionRegistry = httpSecurity.getSharedObject(SessionRegistry.class);
            if(sessionRegistry != null) {
                authenticationProvider.setSessionRegistry(sessionRegistry);
            }
        }));
        authenticationConverters.item(new OAuth2AuthorizationCodeAuthenticationConverter());
        return this;
    }

    public TokenEndpointConfigurer withClientCredentials() {
        authenticationProviders.supply(supplyAuthenticationProvider(OAuth2ClientCredentialsAuthenticationProvider::new));
        authenticationConverters.item(new OAuth2ClientCredentialsAuthenticationConverter());
        return this;
    }

    public TokenEndpointConfigurer withTokenExchange() {
        authenticationProviders.supply(supplyAuthenticationProvider(OAuth2TokenExchangeAuthenticationProvider::new));
        authenticationConverters.item(new OAuth2TokenExchangeAuthenticationConverter());
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
        var tokenEndpointFilter = new OAuth2TokenEndpointFilter(
                authenticationManager,
                tokenEndpoint.getPath()
        );

        tokenEndpointFilter.setAuthenticationConverter(new DelegatingAuthenticationConverter(this.authenticationConverters.apply(httpSecurity)));

        if(accessTokenResponseHandler != null) {
            tokenEndpointFilter.setAuthenticationSuccessHandler(accessTokenResponseHandler);
        }

        if(errorResponseHandler != null) {
            tokenEndpointFilter.setAuthenticationFailureHandler(errorResponseHandler);
        }

        httpSecurity.addFilterAfter(new DelegatingRequestMatcherFilter(getEndpointsMatcher(), postProcess(tokenEndpointFilter)), AuthorizationFilter.class);
    }

    public RequestMatcher getEndpointsMatcher() {
        return new DeferredRequestMatcher(() -> tokenEndpoint.getMatcher());
    }
}
