package com.contentgrid.tokenmonger.configuration;

import com.contentgrid.tokenmonger.IssuerContext;
import com.contentgrid.tokenmonger.IssuerContext.IssuerType;
import com.contentgrid.tokenmonger.TokenmongerProperties;
import com.contentgrid.tokenmonger.oauth2.OAuth2ServerConfiguration;
import com.contentgrid.tokenmonger.oauth2.token.decoder.TokenDecoder;
import com.contentgrid.tokenmonger.web.UserExtensionAccessTokenController;
import com.contentgrid.tokenmonger.web.mapping.HostRequestCondition;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class UserExtensionAccessTokenConfiguration {
	private final CommonConfigurationFactory configurationFactory;


	@Bean
	@IssuerContext(IssuerType.USER_EXTENSION_ACCESS_TOKEN)
	public JWKSource<SecurityContext> ueatJwkSource(
			TokenmongerProperties tokenmongerProperties
	) {
		return configurationFactory.jwkSource(tokenmongerProperties.getUserExtensionAccess());
	}

	@Bean
	@IssuerContext(IssuerType.USER_EXTENSION_ACCESS_TOKEN)
	public OAuth2ServerConfiguration ueatOAuth2ServerConfiguration(
			TokenmongerProperties tokenmongerProperties,
			@IssuerContext(IssuerType.USER_EXTENSION_ACCESS_TOKEN) JWKSource<SecurityContext> jwkSource
	) {
		return configurationFactory.oauth2ServerConfiguration(tokenmongerProperties.getUserExtensionAccess(), jwkSource);
	}

	@Bean
	@IssuerContext(IssuerType.USER_EXTENSION_ACCESS_TOKEN)
	public TokenDecoder<Jwt> ueatTokenDecoder(
			TokenmongerProperties tokenmongerProperties,
			@IssuerContext(IssuerType.USER_EXTENSION_ACCESS_TOKEN) JWKSource<SecurityContext> jwkSource
	) {
		return configurationFactory.tokenDecoder(tokenmongerProperties.getUserExtensionAccess(), jwkSource);
	}


	@Bean
	@IssuerContext(IssuerType.USER_APPLICATION_ACCESS_TOKEN)
	public JwtDecoder uaatJwtDecoder(
			TokenmongerProperties tokenmongerProperties
	) {
		return configurationFactory.jwtDecoder(tokenmongerProperties.getUserApplicationAccess());
	}

	@Bean
	@Order(1)
	public SecurityFilterChain ueatSecurityFilterChain(
			HttpSecurity http,
			@IssuerContext(IssuerType.USER_APPLICATION_ACCESS_TOKEN)
			JwtDecoder uaatJwtDecoder,
			@IssuerContext(IssuerType.USER_EXTENSION_ACCESS_TOKEN)
			OAuth2ServerConfiguration oAuth2ServerConfiguration
	) throws Exception {
		var issuerHost = URI.create(oAuth2ServerConfiguration.getIssuer()).getHost();
		return http.securityMatcher(UserExtensionAccessTokenController.CONTENTGRID_AUTHENTICATION_EXTERNAL_TOKEN_PATH)
				.securityMatchers(matcher -> {
					matcher.requestMatchers(UserExtensionAccessTokenController.CONTENTGRID_AUTHENTICATION_EXTERNAL_TOKEN_PATH)
							.requestMatchers(new NegatedRequestMatcher(new HostRequestCondition(Set.of(issuerHost))));
				})
				.authorizeHttpRequests(req -> req.anyRequest().authenticated())
				.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(uaatJwtDecoder)))
				.build();
	}

}
