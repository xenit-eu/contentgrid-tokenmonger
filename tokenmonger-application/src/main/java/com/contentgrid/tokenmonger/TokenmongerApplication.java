package com.contentgrid.tokenmonger;

import com.contentgrid.tokenmonger.extensions.registration.InMemoryRegisteredExtensionRepository;
import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtensionRepository;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import java.util.List;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;

@SpringBootApplication
@EnableConfigurationProperties({UserToExtensionProperties.class, ExtensionToAppProperties.class, ExtensionProperties.class})
public class TokenmongerApplication {

	public static void main(String[] args) {
		SpringApplication.run(TokenmongerApplication.class, args);
	}

	@Bean
	OAuth2AuthorizationService authorizationService() {
		return new InMemoryOAuth2AuthorizationService();
	}

	@Bean
	RegisteredExtensionRepository inMemoryRegisteredExtensionRepository(ExtensionProperties extensionProperties) {
		return new InMemoryRegisteredExtensionRepository(extensionProperties.getRegistration().values());
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


}
