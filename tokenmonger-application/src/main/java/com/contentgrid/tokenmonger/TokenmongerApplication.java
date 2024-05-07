package com.contentgrid.tokenmonger;

import com.contentgrid.tokenmonger.IssuerContext.IssuerType;
import com.contentgrid.tokenmonger.authentication.AuthorizationGrantExtensions;
import com.contentgrid.tokenmonger.authentication.UserToExtensionTokenExchangeAuthenticationConverter;
import com.contentgrid.tokenmonger.authentication.UserToExtensionTokenExchangeAuthenticationProvider;
import com.contentgrid.tokenmonger.clientregistration.InMemoryRegisteredClientRepository;
import com.contentgrid.tokenmonger.clientregistration.RegisteredClientRepository;
import com.contentgrid.tokenmonger.configuration.AuthorizationServerContextConfigurer;
import com.contentgrid.tokenmonger.configuration.AuthorizationServerMetadataEndpointConfigurer;
import com.contentgrid.tokenmonger.configuration.EndpointConfiguration;
import com.contentgrid.tokenmonger.configuration.JwkSetEndpointConfigurer;
import com.contentgrid.tokenmonger.configuration.ServicesConfigurer;
import com.contentgrid.tokenmonger.configuration.TokenEndpointConfigurer;
import com.contentgrid.tokenmonger.jwk.source.ExpiredJWKFilteringJWKSource;
import com.contentgrid.tokenmonger.jwk.source.FilebasedJWKSetSource;
import com.contentgrid.tokenmonger.jwk.source.LoggingJWKSetSourceEventListener;
import com.contentgrid.tokenmonger.jwk.source.RandomJWKSelectionJWKSource;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.oauth2.client.AuthorizationCodeGrantDsl;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;

@SpringBootApplication
@EnableConfigurationProperties(TokenMongerUserToExtensionProperties.class)
public class TokenmongerApplication {

	public static void main(String[] args) {
		SpringApplication.run(TokenmongerApplication.class, args);
	}

	@Bean
	OAuth2AuthorizationService authorizationService() {
		return new InMemoryOAuth2AuthorizationService();
	}

	@Bean
	public InMemoryRegisteredClientRepository registeredClientRepository() {
		return new InMemoryRegisteredClientRepository(List.of(
				RegisteredClient.withId("test")
						.clientId("test")
						.clientSecret("{noop}test")
						.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
						.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
						.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
						.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
						.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
						.authorizationGrantType(AuthorizationGrantExtensions.CONTENTGRID_EXTENSION_TOKEN_GRANT_TYPE)
						.redirectUri("http://localhost/oauth2")
						.clientSettings(ClientSettings.builder()
								.setting(InMemoryRegisteredClientRepository.RESOURCE_URI_SETTING, List.of(
										"http://example.com/",
										"http://example.org/"
								))
								.build())
						.build()
		));
	}

	@Bean
	InitializingBean verifyJWKSourcesAtStartup(
			List<JWKSource<SecurityContext>> jwkSources
	) {
		return () -> {
			for (JWKSource<SecurityContext> jwkSource : jwkSources) {
				var signingKeys = jwkSource.get(new JWKSelector(new JWKMatcher.Builder()
						.keyUse(KeyUse.SIGNATURE)
						.build()), new SimpleSecurityContext());

				if(signingKeys.isEmpty()) {
					throw new RuntimeException("All JWK sources must have signing keys. Missing signing keys in source %s".formatted(jwkSource));
				}
			}
		};
	}

	@Bean
	@IssuerContext(IssuerType.USER_TO_EXTENSION)
	public JWKSource<SecurityContext> userToExtensionJwkSource(
			TokenMongerUserToExtensionProperties userToExtensionProperties,
			ResourcePatternResolver resourcePatternResolver
	) {
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
			@IssuerContext(IssuerType.USER_TO_EXTENSION) JWKSource<SecurityContext> jwkSource
	) {
		return new JwtGenerator(
				new NimbusJwtEncoder(new RandomJWKSelectionJWKSource<>(new ExpiredJWKFilteringJWKSource<>(jwkSource)))
		);
	}

	@Bean
	@Order(1)
	public SecurityFilterChain userToExtensionInAppSecurityFilterChain(
			HttpSecurity http,
			OAuth2AuthorizationService authorizationService,
			RegisteredClientRepository registeredClientRepository,
			TokenMongerUserToExtensionProperties userToExtensionProperties,
			@IssuerContext(IssuerType.USER_TO_EXTENSION) OAuth2TokenGenerator<?> tokenGenerator,
			@IssuerContext(IssuerType.USER_TO_EXTENSION) JWKSource<SecurityContext> jwkSource
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
							registeredClientRepository
					))
					.tokenEndpoint(endpoints.getTokenEndpoint())
			;
		});

		http.securityMatcher(endpoints.getRequestMatcher())
				.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
				.csrf(csrf -> csrf.ignoringRequestMatchers(endpoints.getTokenEndpoint().getMatcher()));

		http.oauth2ResourceServer(resourceServer -> {
			resourceServer.jwt(jwt -> {
				jwt.jwkSetUri(userToExtensionProperties.getJwkSetUri());
			});
		});

		return http.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain userToExtensionSharedSecurityFilterChain(
			HttpSecurity http,
			TokenMongerUserToExtensionProperties userToExtensionProperties,
			@IssuerContext(IssuerType.USER_TO_EXTENSION) OAuth2TokenGenerator<?> tokenGenerator,
			@IssuerContext(IssuerType.USER_TO_EXTENSION) JWKSource<SecurityContext> jwkSource
	)
			throws Exception {
		var issuerHost = userToExtensionProperties.getIssuer().getAuthority();
		var endpoints = new EndpointConfiguration()
				.baseMatcher(new RequestHeaderRequestMatcher("Host", issuerHost))
				.issuer(userToExtensionProperties.getIssuer())
				//.tokenEndpoint("/authentication/external/token")
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

		/*
		http.with(new ClientAuthenticationConfigurer(), clientAuthenticationConfigurer -> {
			clientAuthenticationConfigurer
					.endpoint(endpoints.getTokenEndpoint())
					.endpoint(endpoints.getTokenIntrospectionEndpoint())
					.endpoint(endpoints.getTokenRevocationEndpoint())
					.clientSecret();
		});

		http.with(new TokenEndpointConfigurer(), tokenEndpoint -> {
			tokenEndpoint
					.withAuthorizationCode()
					.tokenEndpoint(endpoints.getTokenEndpoint())
			;
		});
		*/

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

	/*
	@Bean
	@Order(3)
	public SecurityFilterChain extensionToAppSecurityFilterChain(HttpSecurity http) throws Exception {
		var endpoints = new EndpointConfiguration()
				.tokenEndpoint("/authentication/delegated/token")
				.tokenRevocationEndpoint("/authentication/delegated/revoke")
				.jwkSetEndpoint("/authentication/delegated/jwks");

		http.with(new ServicesConfigurer(), services -> {

		});
		http.with(new ClientAuthenticationConfigurer(), clientAuthenticationConfigurer -> {
			clientAuthenticationConfigurer
					.endpoint(endpoints.getTokenEndpoint())
					.endpoint(endpoints.getTokenRevocationEndpoint())
					.clientSecret();
		});
		http.with(new TokenEndpointConfigurer(), tokenEndpoint -> {
			tokenEndpoint
					.withClientCredentials()
					.withTokenExchange()
					.tokenEndpoint(endpoints.getTokenEndpoint())
			;
		});

		http.securityMatcher(endpoints.getRequestMatcher())
				.authorizeHttpRequests(authorize -> {
					authorize.requestMatchers(endpoints.getJwkSetEndpoint().getMatcher()).anonymous();
					authorize.anyRequest().authenticated();
				})
				.csrf(csrf -> csrf.ignoringRequestMatchers(endpoints.getRequestMatcher()));

		http.exceptionHandling((exceptions) -> exceptions
				.authenticationEntryPoint(new Http403ForbiddenEntryPoint())
		);

		return http.build();
	}
	 */
}
