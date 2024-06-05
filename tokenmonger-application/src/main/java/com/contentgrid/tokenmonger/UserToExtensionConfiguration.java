package com.contentgrid.tokenmonger;

import com.contentgrid.tokenmonger.IssuerContext.IssuerType;
import com.contentgrid.tokenmonger.authentication.JwtWithCompositeActorsAuthenticationConverter;
import com.contentgrid.tokenmonger.authentication.UserToExtensionTokenExchangeAuthenticationConverter;
import com.contentgrid.tokenmonger.authentication.UserToExtensionTokenExchangeAuthenticationProvider;
import com.contentgrid.tokenmonger.configuration.AuthorizationServerContextConfigurer;
import com.contentgrid.tokenmonger.configuration.AuthorizationServerMetadataEndpointConfigurer;
import com.contentgrid.tokenmonger.configuration.AuthorizeEndpointConfigurer;
import com.contentgrid.tokenmonger.configuration.ClientAuthenticationConfigurer;
import com.contentgrid.tokenmonger.configuration.EndpointConfiguration;
import com.contentgrid.tokenmonger.configuration.JwkSetEndpointConfigurer;
import com.contentgrid.tokenmonger.configuration.ServicesConfigurer;
import com.contentgrid.tokenmonger.configuration.TokenEndpointConfigurer;
import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtensionRepository;
import com.contentgrid.tokenmonger.jwk.source.ExpiredJWKFilteringJWKSource;
import com.contentgrid.tokenmonger.jwk.source.FilebasedJWKSetSource;
import com.contentgrid.tokenmonger.jwk.source.LoggingJWKSetSourceEventListener;
import com.contentgrid.tokenmonger.jwk.source.RandomJWKSelectionJWKSource;
import com.contentgrid.tokenmonger.token.JwtTokenCustomizerBuilder;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import java.net.MalformedURLException;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;

@Configuration(proxyBeanMethods = false)
public class UserToExtensionConfiguration {

    @Bean
    @IssuerContext(IssuerType.USER_TO_EXTENSION)
    public JWKSource<SecurityContext> userToExtensionJwkSource(
            UserToExtensionProperties userToExtensionProperties,
            ResourcePatternResolver resourcePatternResolver
    ) {
        if(userToExtensionProperties.getActiveSigningKeys() == null) {
            return null;
        }
        var fileJwkSource = new FilebasedJWKSetSource(
                resourcePatternResolver,
                userToExtensionProperties.getActiveSigningKeys(),
                userToExtensionProperties.getRetiredSigningKeys()
        );
        return JWKSourceBuilder.create(fileJwkSource)
                .refreshAheadCache(JWKSourceBuilder.DEFAULT_REFRESH_AHEAD_TIME, true, new LoggingJWKSetSourceEventListener<>())
                .build();
    }


    @Bean
    @IssuerContext(IssuerType.USER_TO_EXTENSION)
    public OAuth2TokenGenerator<?> userToExtensionTokenGenerator(
            @IssuerContext(IssuerType.USER_TO_EXTENSION) JWKSource<SecurityContext> jwkSource,
            RegisteredExtensionRepository extensionRepository,
            ExtensionProperties extensionProperties
    ) throws MalformedURLException {
        var generator = new JwtGenerator(
                new NimbusJwtEncoder(new RandomJWKSelectionJWKSource<>(new ExpiredJWKFilteringJWKSource<>(jwkSource)))
        );
        generator.setJwtCustomizer(
                JwtTokenCustomizerBuilder.create()
                        .actorsFromAuthentication()
                        .expiryFromOriginalToken()
                        .mayActFromRegisteredClient(extensionProperties.getIssuer().toURL(), extensionRepository)
                        .subjectBasedOnOriginalToken()
                        .customizer(context -> {
                            var extension = extensionRepository.findByClientId(context.getRegisteredClient().getClientId()).orElseThrow();
                            context.getClaims().audience(List.of("contentgrid:extension:"+extension.getExtensionId()));
                        })
                        .claimsFromOriginalToken(name -> name.startsWith("restrict:"))
                        .claimsFromOriginalToken(name -> name.startsWith("context:"))
                        .build()
        );
        return generator;
    }

    @Bean
    @IssuerContext(IssuerType.USER_TO_EXTENSION)
    public JwtDecoder userToExtensionJwtDecoder(
            UserToExtensionProperties userToExtensionProperties
    ) {
        var jwtDecoder = NimbusJwtDecoder.withJwkSetUri(userToExtensionProperties.getJwkSetUri()).build();

        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithValidators(
                        new JwtClaimValidator<List<String>>(JwtClaimNames.AUD, (aud) -> aud != null && aud.contains("contentgrid:system:endpoints:authentication"))
                )
        ));
        return jwtDecoder;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain userToExtensionInAppSecurityFilterChain(
            HttpSecurity http,
            OAuth2AuthorizationService authorizationService,
            RegisteredExtensionRepository registeredExtensionRepository,
            RegisteredClientRepository registeredClientRepository,
            UserToExtensionProperties userToExtensionProperties,
            @IssuerContext(IssuerType.USER_TO_EXTENSION) OAuth2TokenGenerator<?> tokenGenerator,
            @IssuerContext(IssuerType.USER_TO_EXTENSION) JWKSource<SecurityContext> jwkSource,
            @IssuerContext(IssuerType.USER_TO_EXTENSION) JwtDecoder jwtDecoder
    )
            throws Exception {


        var issuerHost = userToExtensionProperties.getIssuer().getAuthority();

        var endpoints = new EndpointConfiguration()
                .issuer(userToExtensionProperties.getIssuer())
                .baseMatcher(new NegatedRequestMatcher(new RequestHeaderRequestMatcher("Host", issuerHost)))
                .tokenEndpoint("/.contentgrid/authentication/external/token")
                .authorizationEndpoint("/.contentgrid/authentication/external/authorize");

        http.with(new ServicesConfigurer(), services -> {
            services.jwkSource(jwkSource);
            services.tokenGenerator(tokenGenerator);
            services.authorizationService(authorizationService);
            services.registeredClientRepository(registeredClientRepository);
        });

        http.with(new AuthorizationServerContextConfigurer(), context -> {
            context.endpoints(endpoints);
        });

        http.with(new TokenEndpointConfigurer(), tokenEndpoint -> {
            tokenEndpoint
                    .authenticationConverter(new UserToExtensionTokenExchangeAuthenticationConverter())
                    .authenticationProvider(new UserToExtensionTokenExchangeAuthenticationProvider(
                            authorizationService,
                            tokenGenerator,
                            registeredExtensionRepository,
                            registeredClientRepository
                    ))
                    .tokenEndpoint(endpoints.getTokenEndpoint())
            ;
        });

        http.with(new AuthorizeEndpointConfigurer(), authorizeEndpoint -> {
            authorizeEndpoint
                    .authorizeEndpoint(endpoints.getAuthorizationEndpoint())
                    .withAuthorizationCode();
        });

        http.securityMatcher(endpoints.getRequestMatcher())
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpoints.getTokenEndpoint().getMatcher()));

        http.oauth2ResourceServer(resourceServer -> {
            resourceServer.jwt(jwt -> {
                jwt.decoder(jwtDecoder);
                jwt.jwtAuthenticationConverter(new JwtWithCompositeActorsAuthenticationConverter(new JwtAuthenticationConverter()));
            });
        });


        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain userToExtensionSharedSecurityFilterChain(
            HttpSecurity http,
            UserToExtensionProperties userToExtensionProperties,
            @IssuerContext(IssuerType.USER_TO_EXTENSION) OAuth2TokenGenerator<?> tokenGenerator,
            @IssuerContext(IssuerType.USER_TO_EXTENSION) JWKSource<SecurityContext> jwkSource
    )
            throws Exception {
        var issuerHost = userToExtensionProperties.getIssuer().getAuthority();
        var endpoints = new EndpointConfiguration()
                .baseMatcher(new RequestHeaderRequestMatcher("Host", issuerHost))
                .issuer(userToExtensionProperties.getIssuer())
                .tokenEndpoint("/authentication/external/token")
                //.tokenIntrospectionEndpoint("/authentication/external/introspect")
                //.tokenRevocationEndpoint("/authentication/external/revoke")
                .jwkSetEndpoint("/authentication/external/jwks")
                ;

        http.with(new ServicesConfigurer(), services -> {
            services.jwkSource(jwkSource);
            services.tokenGenerator(tokenGenerator);
        });

        http.with(new AuthorizationServerContextConfigurer(), context -> {
            context.endpoints(endpoints);
        });

        http.with(new ClientAuthenticationConfigurer(), clientAuthenticationConfigurer -> {
            clientAuthenticationConfigurer
                    .endpoint(endpoints.getTokenEndpoint())
                    /*
                    .endpoint(endpoints.getTokenIntrospectionEndpoint())
                    .endpoint(endpoints.getTokenRevocationEndpoint())
                     */
                    .clientSecret();
        });

        http.with(new TokenEndpointConfigurer(), tokenEndpoint -> {
            tokenEndpoint
                    .withAuthorizationCode()
                    .tokenEndpoint(endpoints.getTokenEndpoint())
            ;
        });

        http.with(new JwkSetEndpointConfigurer(), jwkSetEndpoint -> {
            jwkSetEndpoint
                    .jwkSetEndpoint(endpoints.getJwkSetEndpoint());
        });

        http.with(new AuthorizationServerMetadataEndpointConfigurer(), authorizationServerMetadataConfigurer -> {
            authorizationServerMetadataConfigurer.endpoints(endpoints);
            authorizationServerMetadataConfigurer.authorizationServerMetadataCustomizer(authorizationServerMetadata -> {
                authorizationServerMetadata
                        .responseType(OAuth2AuthorizationResponseType.CODE.getValue())
                        .grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                        .codeChallengeMethod("S256")
                ;
            });
        });


        http.securityMatcher(endpoints.getRequestMatcher())
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpoints.getRequestMatcher()));

        http.exceptionHandling((exceptions) -> exceptions
                .authenticationEntryPoint(new Http403ForbiddenEntryPoint())
        );

        return http.build();
    }

}
