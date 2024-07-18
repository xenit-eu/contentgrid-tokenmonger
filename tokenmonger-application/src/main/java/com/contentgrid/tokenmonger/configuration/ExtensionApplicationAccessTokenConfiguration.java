package com.contentgrid.tokenmonger.configuration;

import com.contentgrid.tokenmonger.ExtensionRegistrationProperties;
import com.contentgrid.tokenmonger.IssuerContext;
import com.contentgrid.tokenmonger.IssuerContext.IssuerType;
import com.contentgrid.tokenmonger.TokenmongerProperties;
import com.contentgrid.tokenmonger.oauth2.OAuth2ServerConfiguration;
import com.contentgrid.tokenmonger.oauth2.token.decoder.TokenDecoder;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;

@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ExtensionApplicationAccessTokenConfiguration {
	private final CommonConfigurationFactory configurationFactory;


	@Bean
	@IssuerContext(IssuerType.EXTENSION_APPLICATION_ACCESS_TOKEN)
	public JWKSource<SecurityContext> eaatJwkSource(
			TokenmongerProperties tokenmongerProperties
	) {
		return configurationFactory.jwkSource(tokenmongerProperties.getExtensionApplicationAccess());
	}

	@Bean
	@IssuerContext(IssuerType.EXTENSION_APPLICATION_ACCESS_TOKEN)
	public OAuth2ServerConfiguration eaatOAuth2ServerConfiguration(
			TokenmongerProperties tokenmongerProperties,
			@IssuerContext(IssuerType.EXTENSION_APPLICATION_ACCESS_TOKEN) JWKSource<SecurityContext> jwkSource
	) {
		return configurationFactory.oauth2ServerConfiguration(tokenmongerProperties.getExtensionApplicationAccess(), jwkSource);
	}

	@Bean
	@IssuerContext(IssuerType.EXTENSION_APPLICATION_ACCESS_TOKEN)
	public TokenDecoder<Jwt> eaatTokenDecoder(
			TokenmongerProperties tokenmongerProperties,
			@IssuerContext(IssuerType.EXTENSION_APPLICATION_ACCESS_TOKEN) JWKSource<SecurityContext> jwkSource
	) {
		return configurationFactory.tokenDecoder(tokenmongerProperties.getExtensionApplicationAccess(), jwkSource);
	}

}
