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
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;

@Configuration(proxyBeanMethods = false)
public class ExtensionConfiguration {
	@Bean
	@IssuerContext(IssuerType.EXTENSION_SYSTEM)
	public JWKSource<SecurityContext> extensionJwkSource(
			ExtensionProperties extensionProperties,
			ResourcePatternResolver resourcePatternResolver
	) {
		if(extensionProperties.getActiveSigningKeys() == null) {
			return null;
		}

		var fileJwkSource = new FilebasedJWKSetSource(
				resourcePatternResolver,
				extensionProperties.getActiveSigningKeys(),
				extensionProperties.getRetiredSigningKeys()
		);

		return JWKSourceBuilder.create(fileJwkSource)
				.refreshAheadCache(JWKSourceBuilder.DEFAULT_REFRESH_AHEAD_TIME, true, new LoggingJWKSetSourceEventListener<>())
				.build();
	}

	@Bean
	@IssuerContext(IssuerType.EXTENSION_SYSTEM)
	public OAuth2TokenGenerator<?> extensionTokenGenerator(
			@IssuerContext(IssuerType.EXTENSION_SYSTEM) JWKSource<SecurityContext> jwkSource,
			RegisteredExtensionRepository extensionRepository,
			ExtensionProperties extensionProperties
	) {
		var generator = new JwtGenerator(
				new NimbusJwtEncoder(new RandomJWKSelectionJWKSource<>(new ExpiredJWKFilteringJWKSource<>(jwkSource)))
		);

		generator.setJwtCustomizer(token -> {
			var extension = extensionRepository.findByClientId(token.getRegisteredClient().getClientId()).orElseThrow();
			token.getClaims()
					.subject(extension.getExtensionId())
					.audience(List.of("contentgrid:system:extensions"));
		});

		return generator;
	}

	@Bean
	@Order(3)
	public SecurityFilterChain extensionSecurityFilterChain(
			HttpSecurity http,
			ExtensionProperties extensionProperties,
			@IssuerContext(IssuerType.EXTENSION_SYSTEM) OAuth2TokenGenerator<?> tokenGenerator,
			@IssuerContext(IssuerType.EXTENSION_SYSTEM) JWKSource<SecurityContext> jwkSource
	) throws Exception {
		var issuerHost = extensionProperties.getIssuer().getAuthority();
		var endpoints = new EndpointConfiguration()
				.baseMatcher(new RequestHeaderRequestMatcher("Host", issuerHost))
				.issuer(extensionProperties.getIssuer())
				.tokenEndpoint("/authentication/system/token")
				//.tokenRevocationEndpoint("/authentication/system/revoke")
				.jwkSetEndpoint("/authentication/system/jwks");

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
					.clientSecret();
		});
		http.with(new TokenEndpointConfigurer(), tokenEndpoint -> {
			tokenEndpoint
					.withClientCredentials()
					.tokenEndpoint(endpoints.getTokenEndpoint())
			;
		});

		http.with(new AuthorizationServerMetadataEndpointConfigurer(), authorizationServerMetadataConfigurer -> {
			authorizationServerMetadataConfigurer.endpoints(endpoints);
		});

		http.securityMatcher(endpoints.getRequestMatcher())
				.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
				.csrf(csrf -> csrf.ignoringRequestMatchers(endpoints.getRequestMatcher()));

		http.exceptionHandling(exceptions -> exceptions
				.authenticationEntryPoint(new Http403ForbiddenEntryPoint())
		);

		return http.build();
	}

}
