package com.contentgrid.tokenmonger;

import static org.assertj.core.api.Assertions.assertThat;

import com.contentgrid.tokenmonger.IssuerContext.IssuerType;
import com.contentgrid.tokenmonger.authentication.AuthorizationGrantExtensions;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSetBasedJWKSource;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.net.URL;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.function.Consumer;
import lombok.SneakyThrows;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.web.util.UriComponentsBuilder;

@SpringBootTest({
        "spring.profiles.active=test"
})
@AutoConfigureMockMvc
class TokenMongerApplicationTokenExchangeTests {

    @Autowired
    MockMvc mockMvc;

    static WireMockServer wireMockServer;

    static JWKSet gatewaySigningKeys = new JWKSet(JWKGenerator.createRandomJWK());

    static JWKSet userToExtensionSigningKeys = new JWKSet(JWKGenerator.createRandomJWK());

    @TestConfiguration
    public static class TestConfig {
        @Bean
        @IssuerContext(IssuerType.USER_TO_EXTENSION)
        @Primary
        public JWKSource<SecurityContext> mockUserToExtensionJwkSource() {
            return new JWKSetBasedJWKSource<>(new StaticJWKSetSource(userToExtensionSigningKeys));
        }

    }

    @BeforeAll
    static void setupWiremock() {
        wireMockServer = new WireMockServer(new WireMockConfiguration().dynamicPort());
        wireMockServer.start();
    }

    @AfterAll
    static void shutdownWiremock() {
        wireMockServer.stop();
    }

    @DynamicPropertySource
    static void configureMockServerPorts(DynamicPropertyRegistry registry) {
        registry.add("contentgrid.tokenmonger.user-to-extension.jwk-set-uri", () -> "http://localhost:"+wireMockServer.port()+"/gateway-jwks.json");

    }

    @BeforeEach
    void setupMockGateway() {
        wireMockServer.stubFor(WireMock.get("/gateway-jwks.json")
                .willReturn(WireMock.okJson(gatewaySigningKeys.toString()))
        );
    }


    static Jwt createGatewayJwt() {
        return createGatewayJwt(jwtClaimsSet -> {

        });
    }

    static Jwt createGatewayJwt(Consumer<JwtClaimsSet.Builder> configurer) {
        var gatewayEncoder = new NimbusJwtEncoder(new JWKSetBasedJWKSource<>(new StaticJWKSetSource(gatewaySigningKeys)));

        var jwtClaimsSetBuilder = JwtClaimsSet.builder()
                .issuer("http://auth.contentgrid.test/realms/xyz")
                .subject("test-user")
                .audience(List.of("contentgrid:system:endpoints:authentication"))
                .claim("context:application:id", "application-id")
                .claim("context:application:domains", List.of("xyz.contentgrid.test"))
                .claim("restrict:principal_claims", "enc:ZZZZ");

        configurer.accept(jwtClaimsSetBuilder);
        return gatewayEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetBuilder.build()));
    }

    @SneakyThrows
    static ResultMatcher isUserToExtensionToken() {
        var decoder = NimbusJwtDecoder.withPublicKey(userToExtensionSigningKeys.getKeys().get(0).toRSAKey()
                        .toRSAPublicKey())
                .build();
        return new AccessTokenJwtMvcResultMatcher(
                decoder,
                jwt -> {
                    assertThat(jwt.getIssuer()).isEqualTo(new URL("http://extensions.contentgrid.test/authentication/external"));
                    assertThat(jwt.getSubject()).isEqualTo("test-user");
                    assertThat(jwt.getClaimAsString("context:application:id")).isEqualTo("application-id");
                    assertThat(jwt.getClaimAsStringList("context:application:domains")).isEqualTo(List.of("xyz.contentgrid.test"));
                    assertThat(jwt.getClaimAsString("restrict:principal_claims")).isEqualTo("enc:ZZZZ");
                    assertThat(jwt.getExpiresAt()).isNotNull()
                            .isBeforeOrEqualTo(Instant.now().plus(5, ChronoUnit.MINUTES));
                }
        );
    }

    @Test
    void exchange_userToExtensionToken_success() throws Exception {
        var gatewayToken = createGatewayJwt();


        mockMvc.perform(MockMvcRequestBuilders.post("/.contentgrid/authentication/external/token")
                        .header("Host", "xyz.contentgrid.test")
                        .header("Authorization", "Bearer "+gatewayToken.getTokenValue())
                        .param("grant_type", AuthorizationGrantExtensions.CONTENTGRID_EXTENSION_TOKEN_GRANT_TYPE.getValue())
                        .param("resource", "http://extension-system.test/xyz")
                ).andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(isUserToExtensionToken());
    }

    @Test
    void authenticate_userToExtension_success() throws Exception {
        var gatewayToken = createGatewayJwt();

        var authorizeResponse = mockMvc.perform(MockMvcRequestBuilders.get("/.contentgrid/authentication/external/authorize")
                .header("Host", "xyz.contentgrid.test")
                .header("Authorization", "Bearer "+gatewayToken.getTokenValue())
                .queryParam("response_type", "code")
                .queryParam("client_id", "test")
                .queryParam("redirect_uri", "http://extension-system.test/oauth2")
                .queryParam("state", "1234")
        ).andExpect(MockMvcResultMatchers.status().is3xxRedirection())
                .andReturn();

        var authorizeRedirectUrl = UriComponentsBuilder.fromUriString(authorizeResponse.getResponse().getRedirectedUrl()).build();

        assertThat(authorizeRedirectUrl.getQueryParams()).containsKey("code");
        assertThat(authorizeRedirectUrl.getQueryParams()).containsEntry("state", List.of("1234"));

        mockMvc.perform(MockMvcRequestBuilders.post("/authentication/external/token")
                .header("Host", "extensions.contentgrid.test")
                .param("client_id", "test")
                .param("client_secret", "test")
                .param("grant_type", AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                .param("code", authorizeRedirectUrl.getQueryParams().getFirst("code"))
                        .param("redirect_uri", "http://extension-system.test/oauth2")
        ).andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(isUserToExtensionToken());

    }

}
