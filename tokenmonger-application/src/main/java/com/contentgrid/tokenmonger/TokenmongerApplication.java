package com.contentgrid.tokenmonger;

import com.contentgrid.tokenmonger.IssuerContext.IssuerType;
import com.contentgrid.tokenmonger.application.InMemoryApplicationRepository;
import com.contentgrid.tokenmonger.configuration.CommonConfigurationFactory;
import com.contentgrid.tokenmonger.extensions.registration.InMemoryRegisteredExtensionRepository;
import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtensionRepository;
import com.contentgrid.tokenmonger.jwk.source.JWKSourceWrapperBuilder;
import com.contentgrid.tokenmonger.oauth2.token.decoder.TokenDecoder;
import com.contentgrid.tokenmonger.web.mapping.TokenmongerRequestMappingHandlerMapping;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import java.time.Clock;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcRegistrations;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

@SpringBootApplication
@EnableConfigurationProperties({ApplicationRegistrationProperties.class, ExtensionRegistrationProperties.class, TokenmongerProperties.class})
public class TokenmongerApplication {

	public static void main(String[] args) {
		SpringApplication.run(TokenmongerApplication.class, args);
	}

	@Bean
	RegisteredExtensionRepository inMemoryRegisteredExtensionRepository(
			ExtensionRegistrationProperties extensionRegistrationProperties
	) {
		return new InMemoryRegisteredExtensionRepository(extensionRegistrationProperties.getRegistration().values());
	}

	@Bean
	InMemoryApplicationRepository inMemoryApplicationRepository(
			ApplicationRegistrationProperties applicationRegistrationProperties
	) {
		return new InMemoryApplicationRepository(applicationRegistrationProperties.getRegistration().values());
	}

	@Bean
	CommonConfigurationFactory configurationFactory(ResourcePatternResolver resourcePatternResolver) {
		return new CommonConfigurationFactory(resourcePatternResolver);
	}

	@Bean
	TokenExpiryPolicy tokenExpiryPolicy() {
		return new TokenExpiryPolicy(
				Duration.of(5, ChronoUnit.MINUTES),
				Clock.systemUTC()
		);
	}

	@Bean
	@IssuerContext(IssuerType.USER_APPLICATION_ACCESS_TOKEN)
	TokenDecoder<Jwt> uaatDecoder(
			CommonConfigurationFactory configurationFactory,
			TokenmongerProperties tokenmongerProperties
	) {
		return configurationFactory.tokenDecoder(tokenmongerProperties.getUserApplicationAccess());
	}

	@Bean
	@IssuerContext(IssuerType.EXTENSION_IDENTITY_TOKEN)
	public TokenDecoder<Jwt> eitTokenDecoder(
			CommonConfigurationFactory configurationFactory,
			TokenmongerProperties tokenmongerProperties
	) {
		return configurationFactory.tokenDecoder(tokenmongerProperties.getExtensionIdentity());
	}

	@Bean
	@Order(3)
	public SecurityFilterChain eaatSecurityFilterChain(
			HttpSecurity http,
			ExtensionRegistrationProperties extensionRegistrationProperties
	) throws Exception {
		return http
				.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
				.csrf(AbstractHttpConfigurer::disable)
				.exceptionHandling(exceptions -> exceptions
						.authenticationEntryPoint(new Http403ForbiddenEntryPoint())
				)
				.build();
	}

	@Bean
	WebMvcRegistrations webMvcRegistrations() {
		return new WebMvcRegistrations() {
			@Override
			public RequestMappingHandlerMapping getRequestMappingHandlerMapping() {
				return new TokenmongerRequestMappingHandlerMapping();
			}
		};
	}

	@Bean
	InitializingBean verifyJWKSourcesAtStartup(
			List<JWKSource<SecurityContext>> jwkSources
	) {
		return () -> {
			for (JWKSource<SecurityContext> jwkSource : jwkSources) {
				var signingKeys = JWKSourceWrapperBuilder.from(jwkSource)
						.filterExpired()
						.build()
						.get(new JWKSelector(new JWKMatcher.Builder()
						.keyUse(KeyUse.SIGNATURE)
						.build()), new SimpleSecurityContext());

				if(signingKeys.isEmpty()) {
					throw new RuntimeException("All JWK sources must have active signing keys. Missing signing keys in source %s".formatted(jwkSource));
				}
			}
		};
	}


}
