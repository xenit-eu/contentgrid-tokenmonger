package com.contentgrid.tokenmonger;

import com.contentgrid.tokenmonger.IssuerContext.IssuerType;
import com.contentgrid.tokenmonger.configuration.AuthorizationServerContextConfigurer;
import com.contentgrid.tokenmonger.configuration.AuthorizationServerMetadataEndpointConfigurer;
import com.contentgrid.tokenmonger.configuration.ClientAuthenticationConfigurer;
import com.contentgrid.tokenmonger.configuration.EndpointConfiguration;
import com.contentgrid.tokenmonger.configuration.ServicesConfigurer;
import com.contentgrid.tokenmonger.configuration.TokenEndpointConfigurer;
import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtensionRepository;
import com.contentgrid.tokenmonger.jwk.source.ExpiredJWKFilteringJWKSource;
import com.contentgrid.tokenmonger.jwk.source.FilebasedJWKSetSource;
import com.contentgrid.tokenmonger.jwk.source.LoggingJWKSetSourceEventListener;
import com.contentgrid.tokenmonger.jwk.source.RandomJWKSelectionJWKSource;
import com.contentgrid.tokenmonger.token.JwtTokenCustomizerBuilder;
import com.contentgrid.tokenmonger.token.RequireActorOAuth2TokenGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import java.util.List;
import java.util.Set;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;

@Configuration(proxyBeanMethods = false)
public class ExtensionToAppConfiguration {
	@Bean
	@IssuerContext(IssuerType.EXTENSION_TO_APP)
	public JWKSource<SecurityContext> extensionToAppJwkSource(
			ExtensionToAppProperties extensionToAppProperties,
			ResourcePatternResolver resourcePatternResolver
	) {
		if(extensionToAppProperties.getActiveSigningKeys() == null) {
			return null;
		}

		var fileJwkSource = new FilebasedJWKSetSource(
				resourcePatternResolver,
				extensionToAppProperties.getActiveSigningKeys(),
				extensionToAppProperties.getRetiredSigningKeys()
		);

		return JWKSourceBuilder.create(fileJwkSource)
				.refreshAheadCache(JWKSourceBuilder.DEFAULT_REFRESH_AHEAD_TIME, true, new LoggingJWKSetSourceEventListener<>())
				.build();
	}

	@Bean
	@IssuerContext(IssuerType.EXTENSION_TO_APP)
	public OAuth2TokenGenerator<?> extensionToAppTokenGenerator(
			@IssuerContext(IssuerType.EXTENSION_TO_APP) JWKSource<SecurityContext> jwkSource,
			RegisteredExtensionRepository extensionRepository,
			ExtensionProperties extensionProperties
	) {
		var generator = new JwtGenerator(
				new NimbusJwtEncoder(new RandomJWKSelectionJWKSource<>(new ExpiredJWKFilteringJWKSource<>(jwkSource)))
		);

		generator.setJwtCustomizer(JwtTokenCustomizerBuilder.create()
				.actorsFromAuthentication()
				.expiryFromOriginalToken()
				.subjectBasedOnOriginalToken()
				.claimBasedOnOriginalToken((originalTokenClaims, tokenClaims) -> {
					tokenClaims.audience(List.of(
							"contentgrid:application:"+originalTokenClaims.getClaimAsString("context:application:id")
					));
				})
				.claimsFromOriginalToken(name -> name.startsWith("restrict:"))
				.claimsFromOriginalToken(name -> name.startsWith("context:"))
				.build());

		return new RequireActorOAuth2TokenGenerator<>(generator);
	}

	@Bean
	@Order(3)
	public SecurityFilterChain extensionToAppSecurityFilterChain(
			HttpSecurity http,
			ExtensionToAppProperties extensionToAppProperties,
			@IssuerContext(IssuerType.EXTENSION_TO_APP) OAuth2TokenGenerator<?> tokenGenerator,
			@IssuerContext(IssuerType.EXTENSION_TO_APP) JWKSource<SecurityContext> jwkSource
	) throws Exception {
		var issuerHost = extensionToAppProperties.getIssuer().getAuthority();
		var endpoints = new EndpointConfiguration()
				.baseMatcher(new RequestHeaderRequestMatcher("Host", issuerHost))
				.issuer(extensionToAppProperties.getIssuer())
				.tokenEndpoint("/authentication/delegated/token")
				//.tokenRevocationEndpoint("/authentication/delegated/revoke")
				.jwkSetEndpoint("/authentication/delegated/jwks");

		http.with(new ServicesConfigurer(), services -> {
			services
					.tokenGenerator(tokenGenerator)
					.jwkSource(jwkSource);

		});

		http.with(new AuthorizationServerContextConfigurer(), context -> {
			context.endpoints(endpoints);
		});

		http.with(new ClientAuthenticationConfigurer(), clientAuthenticationConfigurer -> {
			clientAuthenticationConfigurer
					.endpoint(endpoints.getTokenEndpoint())
					.endpoint(endpoints.getTokenRevocationEndpoint())
					.clientSecret();
		});
		http.with(new TokenEndpointConfigurer(), tokenEndpoint -> {
			tokenEndpoint
					.withTokenExchange()
					.tokenEndpoint(endpoints.getTokenEndpoint())
			;
		});

		http.with(new AuthorizationServerMetadataEndpointConfigurer(), authorizationServerMetadataConfigurer -> {
			authorizationServerMetadataConfigurer.endpoints(endpoints);
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
