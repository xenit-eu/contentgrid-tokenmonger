package com.contentgrid.tokenmonger.configuration;

import com.contentgrid.tokenmonger.configuration.EndpointConfiguration.Endpoint;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.PublicClientAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretPostAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.PublicClientAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

@Accessors(fluent = true, chain = true)
public class ClientAuthenticationConfigurer extends AbstractHttpConfigurer<ClientAuthenticationConfigurer, HttpSecurity> {
    private final ConfigurationFunction<Endpoint> endpoints = new ConfigurationFunction<>(item -> item);

    private final ConfigurationFunction<AuthenticationConverter> authenticationConverters = new ConfigurationFunction<>(this::postProcess);
    private final ConfigurationFunction<AuthenticationProvider> authenticationProviders = new ConfigurationFunction<>(this::postProcess);

    @Setter
    private AuthenticationSuccessHandler authenticationSuccessHandler;

    @Setter
    private AuthenticationFailureHandler authenticationFailureHandler;

    public ClientAuthenticationConfigurer endpoint(@NonNull Endpoint endpoint) {
        this.endpoints.item(endpoint);
        return this;
    }

    public ClientAuthenticationConfigurer authenticationProviders(@NonNull Consumer<List<AuthenticationProvider>> configurer) {
        authenticationProviders.add(configurer);
        return this;
    }

    public ClientAuthenticationConfigurer authenticationProvider(@NonNull AuthenticationProvider authenticationProvider) {
        authenticationProviders.item(authenticationProvider);
        return this;
    }

    public ClientAuthenticationConfigurer authenticationConverters(@NonNull Consumer<List<AuthenticationConverter>> configurer) {
        authenticationConverters.add(configurer);
        return this;
    }

    public ClientAuthenticationConfigurer authenticationConverter(@NonNull AuthenticationConverter authenticationConverter) {
        authenticationConverters.item(authenticationConverter);
        return this;
    }

    public static <T extends AuthenticationProvider> Function<HttpSecurity, T> supplyAuthenticationProvider(
            BiFunction<RegisteredClientRepository, OAuth2AuthorizationService, T> creator,
            BiConsumer<T, HttpSecurity> customizer
    ) {
        return httpSecurity -> {
            var registeredClientRepository = ConfigurerUtils.getRegisteredClientRepository(httpSecurity);
            var authorizationService = ConfigurerUtils.getAuthorizationService(httpSecurity);

            var authenticationProvider = creator.apply(registeredClientRepository, authorizationService);

            customizer.accept(authenticationProvider, httpSecurity);

            return authenticationProvider;
        };
    }
    private static <T extends AuthenticationProvider> Function<HttpSecurity, T> supplyAuthenticationProvider(
            BiFunction<RegisteredClientRepository, OAuth2AuthorizationService, T> creator
    ) {
        return supplyAuthenticationProvider(creator, (authenticationProvider, httpSecurity) -> {

        });
    }

    public ClientAuthenticationConfigurer clientSecret() {
        this.authenticationConverter(new ClientSecretBasicAuthenticationConverter());
        this.authenticationConverter(new ClientSecretPostAuthenticationConverter());

        this.authenticationProviders.supply(supplyAuthenticationProvider(
                ClientSecretAuthenticationProvider::new,
                (authenticationProvider, httpSecurity) -> {
                    var passwordEncoder = ConfigurerUtils.getOptionalBean(httpSecurity, PasswordEncoder.class);
                    if(passwordEncoder != null) {
                        authenticationProvider.setPasswordEncoder(passwordEncoder);
                    }
                }
        ));
        return this;
    }

    public ClientAuthenticationConfigurer publicClient() {
        this.authenticationConverter(new PublicClientAuthenticationConverter());
        this.authenticationProviders.supply(supplyAuthenticationProvider(PublicClientAuthenticationProvider::new));
        return this;
    }

    @Override
    public void init(HttpSecurity httpSecurity) throws Exception {
        this.authenticationProviders
                .apply(httpSecurity)
                .forEach(httpSecurity::authenticationProvider);
    }

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
        var authenticationFilter = new OAuth2ClientAuthenticationFilter(
                authenticationManager,
                new OrRequestMatcher(this.endpoints.apply(httpSecurity).stream().map(Endpoint::getMatcher).toList())
        );

        authenticationFilter.setAuthenticationConverter(new DelegatingAuthenticationConverter(authenticationConverters.apply(httpSecurity)));

        if(authenticationSuccessHandler != null) {
            authenticationFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);;
        }
        if(authenticationFailureHandler != null) {
            authenticationFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
        }

        httpSecurity.addFilterAfter(postProcess(authenticationFilter), AbstractPreAuthenticatedProcessingFilter.class);
    }
}
