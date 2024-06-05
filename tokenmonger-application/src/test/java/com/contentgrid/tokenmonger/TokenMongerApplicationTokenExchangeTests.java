package com.contentgrid.tokenmonger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

import com.contentgrid.tokenmonger.IssuerContext.IssuerType;
import com.contentgrid.tokenmonger.authentication.AuthorizationGrantExtensions;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSetBasedJWKSource;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.net.URL;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import lombok.SneakyThrows;
import org.assertj.core.api.ThrowingConsumer;
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
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.web.util.UriComponentsBuilder;

@SpringBootTest({
        "spring.profiles.active=test"
})
@AutoConfigureMockMvc(printOnlyOnFailure = false)
class TokenMongerApplicationTokenExchangeTests {

    @Autowired
    MockMvc mockMvc;

    static WireMockServer wireMockServer;

    static JWKSet gatewaySigningKeys = new JWKSet(JWKGenerator.createRandomJWK());

    static JWKSet userToExtensionSigningKeys = new JWKSet(JWKGenerator.createRandomJWK());

    static JWKSet extensionToAppSigningKeys = new JWKSet(JWKGenerator.createRandomJWK());

    static JWKSet extensionSigningKeys = new JWKSet(JWKGenerator.createRandomJWK());

    @TestConfiguration
    public static class TestConfig {
        @Bean
        @IssuerContext(IssuerType.USER_TO_EXTENSION)
        @Primary
        public JWKSource<SecurityContext> mockUserToExtensionJwkSource() {
            return new JWKSetBasedJWKSource<>(new StaticJWKSetSource(userToExtensionSigningKeys));
        }

        @Bean
        @IssuerContext(IssuerType.EXTENSION_TO_APP)
        @Primary
        public JWKSource<SecurityContext> mockExtensionToAppJwkSource() {
            return new JWKSetBasedJWKSource<>(new StaticJWKSetSource(extensionToAppSigningKeys));
        }

        @Bean
        @IssuerContext(IssuerType.EXTENSION_SYSTEM)
        @Primary
        public JWKSource<SecurityContext> mockExtensionJwkSource() {
            return new JWKSetBasedJWKSource<>(new StaticJWKSetSource(extensionSigningKeys));
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

    static AccessTokenJwtMvcResultMatcher userToExtensionToken() {
        return accessToken(userToExtensionSigningKeys, jwt -> {
            assertThat(jwt.getIssuer()).isEqualTo(new URL("http://extensions.contentgrid.test/authentication/external"));
            assertThat(jwt.getSubject()).isEqualTo("http://auth.contentgrid.test/realms/xyz#test-user");
            assertThat(jwt.getAudience()).containsExactly("contentgrid:extension:test-extension");
            assertThat(jwt.getClaimAsString("context:application:id")).isEqualTo("application-id");
            assertThat(jwt.getClaimAsStringList("context:application:domains")).isEqualTo(List.of("xyz.contentgrid.test"));
            assertThat(jwt.getClaimAsString("restrict:principal_claims")).isEqualTo("enc:ZZZZ");
            assertThat(jwt.getExpiresAt()).isNotNull()
                    .isBeforeOrEqualTo(Instant.now().plus(5, ChronoUnit.MINUTES));
            assertThat(jwt.getClaimAsMap("may_act")).isEqualTo(Map.of(
                    "iss", "http://extensions.contentgrid.test/authentication/system",
                    "sub", "test-extension"
            ));
        });
    }


    @SneakyThrows
    static AccessTokenJwtMvcResultMatcher accessToken(JWKSet jwkSet, ThrowingConsumer<Jwt> jwtAssertions) {
        var processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, new JWKSetBasedJWKSource<>(new StaticJWKSetSource(jwkSet))));
        processor.setJWTClaimsSetVerifier((claims, context) -> {

        });
        var decoder = new NimbusJwtDecoder(processor);
        return new AccessTokenJwtMvcResultMatcher(
                decoder,
                jwtAssertions
        );
    }

    static MockHttpServletRequestBuilder contentGridTokenGrant(Jwt authorizationJwt) {
        return MockMvcRequestBuilders.post("/.contentgrid/authentication/external/token")
                .header("Host", "xyz.contentgrid.test")
                .header("Authorization", "Bearer "+authorizationJwt.getTokenValue())
                .param("grant_type", AuthorizationGrantExtensions.CONTENTGRID_EXTENSION_TOKEN_GRANT_TYPE.getValue());
    }

    static MockHttpServletRequestBuilder tokenExchange() {
        return MockMvcRequestBuilders.post("/authentication/delegated/token")
                .header("Host", "extensions.contentgrid.test")
                .param("grant_type", AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
    }

    static MockHttpServletRequestBuilder tokenExchange(Jwt subjectToken, Jwt actorToken) {
        var requestBuilder = tokenExchange();
        if(subjectToken != null) {
                requestBuilder  = requestBuilder.param("subject_token", subjectToken.getTokenValue())
                    .param("subject_token_type", "urn:ietf:params:oauth:token-type:access_token");
        }
        if(actorToken != null) {
                requestBuilder = requestBuilder.param("actor_token", actorToken.getTokenValue())
                    .param("actor_token_type", "urn:ietf:params:oauth:token-type:access_token");
        }
        return requestBuilder.param("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
                .param("client_id", "test-client")
                .param("client_secret", "test-client-secret");
    }

    static MockHttpServletRequestBuilder clientCredentials(String clientId, String clientSecret) {
        return MockMvcRequestBuilders.post("/authentication/system/token")
                .header("Host", "extensions.contentgrid.test")
                .param("grant_type", AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                .param("client_id", clientId)
                .param("client_secret", clientSecret);
    }

    enum TokenType {
        USER,
        USER_TO_EXTENSION,
        EXTENSION_TO_APP,
        EXTENSION_SERVICE_ACCOUNT
    }

    private Jwt retrieveToken(TokenType tokenType) throws Exception {
        return switch (tokenType) {
            case USER -> createGatewayJwt();
            case USER_TO_EXTENSION -> accessToken(userToExtensionSigningKeys, jwt -> {}).apply(
                    mockMvc.perform(contentGridTokenGrant(retrieveToken(TokenType.USER))
                            .param("resource", "http://extension-system.test/xyz")
                    ).andExpect(MockMvcResultMatchers.status().isOk()).andReturn());
            case EXTENSION_SERVICE_ACCOUNT -> accessToken(extensionSigningKeys, jwt -> {}).apply(mockMvc.perform(clientCredentials("test-client", "test-client-secret")).andExpect(MockMvcResultMatchers.status().isOk()).andReturn());
            case EXTENSION_TO_APP -> accessToken(extensionToAppSigningKeys, jwt -> {}).apply(mockMvc.perform(tokenExchange(retrieveToken(TokenType.USER_TO_EXTENSION), retrieveToken(TokenType.EXTENSION_SERVICE_ACCOUNT))).andExpect(MockMvcResultMatchers.status().isOk()).andReturn());
        };
    }

    @Test
    void exchange_userToExtensionToken_success() throws Exception {
        var gatewayToken = createGatewayJwt();

        mockMvc.perform(contentGridTokenGrant(gatewayToken)
                        .param("resource", "http://extension-system.test/xyz")
                )
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(userToExtensionToken());
    }

    @Test
    void exchange_userToExtensionToken_invalidAudience() throws Exception {
        var gatewayToken = createGatewayJwt(jwt -> jwt.audience(List.of("invalid_audience")));

        mockMvc.perform(contentGridTokenGrant(gatewayToken)
                        .param("resource", "http://extension-system.test/xyz")
                )
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());
    }

    @Test
    void exchange_userToExtensionToken_expiredToken() throws Exception {
        var gatewayToken = createGatewayJwt(jwt -> jwt.expiresAt(Instant.now().minus(1, ChronoUnit.MINUTES)));

        mockMvc.perform(contentGridTokenGrant(gatewayToken)
                        .param("resource", "http://extension-system.test/xyz")
                )
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());
    }

    @Test
    void exchange_userToExtensionToken_shortlyExpiringToken() throws Exception {
        var expiryTime = Instant.now().plus(1, ChronoUnit.MINUTES);
        var gatewayToken = createGatewayJwt(jwt -> jwt.expiresAt(expiryTime));

        mockMvc.perform(contentGridTokenGrant(gatewayToken)
                        .param("resource", "http://extension-system.test/xyz")
                )
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(accessToken(userToExtensionSigningKeys, jwt -> {
                    assertThat(jwt.getExpiresAt()).isCloseTo(expiryTime, within(1, ChronoUnit.SECONDS));
                }));
    }

    @Test
    void exchange_userToExtensionToken_longExpiringToken() throws Exception {
        var expiryTime = Instant.now().plus(10, ChronoUnit.HOURS);
        var gatewayToken = createGatewayJwt(jwt -> jwt.expiresAt(expiryTime));

        mockMvc.perform(contentGridTokenGrant(gatewayToken)
                        .param("resource", "http://extension-system.test/xyz")
                )
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(accessToken(userToExtensionSigningKeys, jwt -> {
                    assertThat(jwt.getExpiresAt()).isCloseTo(Instant.now().plus(5, ChronoUnit.MINUTES), within(30, ChronoUnit.SECONDS));
                }));
    }

    @Test
    void authenticate_userToExtension_success() throws Exception {
        var gatewayToken = createGatewayJwt();

        var authorizeResponse = mockMvc.perform(MockMvcRequestBuilders.get("/.contentgrid/authentication/external/authorize")
                .header("Host", "xyz.contentgrid.test")
                .header("Authorization", "Bearer "+gatewayToken.getTokenValue())
                .queryParam("response_type", "code")
                .queryParam("client_id", "test-client")
                .queryParam("redirect_uri", "http://extension-system.test/oauth2")
                .queryParam("state", "1234")
        ).andExpect(MockMvcResultMatchers.status().is3xxRedirection())
                .andReturn();

        var authorizeRedirectUrl = UriComponentsBuilder.fromUriString(authorizeResponse.getResponse().getRedirectedUrl()).build();

        assertThat(authorizeRedirectUrl.getQueryParams()).containsKey("code");
        assertThat(authorizeRedirectUrl.getQueryParams()).containsEntry("state", List.of("1234"));

        // Impersonating the extension
        mockMvc.perform(MockMvcRequestBuilders.post("/authentication/external/token")
                .header("Host", "extensions.contentgrid.test")
                .param("client_id", "test-client")
                .param("client_secret", "test-client-secret")
                .param("grant_type", AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                .param("code", authorizeRedirectUrl.getQueryParams().getFirst("code"))
                        .param("redirect_uri", "http://extension-system.test/oauth2")
        ).andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(userToExtensionToken());

        // Validate that we cannot exchange the token twice
        mockMvc.perform(MockMvcRequestBuilders.post("/authentication/external/token")
                        .header("Host", "extensions.contentgrid.test")
                        .param("client_id", "test-client")
                        .param("client_secret", "test-client-secret")
                        .param("grant_type", AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                        .param("code", authorizeRedirectUrl.getQueryParams().getFirst("code"))
                        .param("redirect_uri", "http://extension-system.test/oauth2")
                ).andExpect(MockMvcResultMatchers.status().is4xxClientError());

    }

    @Test
    void jwks_userToExtension() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/authentication/external/jwks")
                        .header("Host", "extensions.contentgrid.test")
                )
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().json(userToExtensionSigningKeys.toString(true)));
    }


    @Test
    void exchange_extensionToApp_success() throws Exception {
        var userToExtensionToken = retrieveToken(TokenType.USER_TO_EXTENSION);
        mockMvc.perform(tokenExchange(userToExtensionToken, retrieveToken(TokenType.EXTENSION_SERVICE_ACCOUNT)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(accessToken(extensionToAppSigningKeys, jwt -> {
                    assertThat(jwt.getIssuer()).hasToString("http://extensions.contentgrid.test/authentication/delegated");
                    assertThat(jwt.getSubject()).isEqualTo("http://auth.contentgrid.test/realms/xyz#test-user");
                    assertThat(jwt.getClaimAsMap("act"))
                            .containsEntry("iss", "http://extensions.contentgrid.test/authentication/system")
                            .containsEntry("sub", "test-extension");

                    assertThat(jwt.getClaimAsString("context:application:id")).isEqualTo("application-id");
                    assertThat(jwt.getClaimAsStringList("context:application:domains")).isEqualTo(List.of("xyz.contentgrid.test"));
                    assertThat(jwt.getClaimAsString("restrict:principal_claims")).isEqualTo("enc:ZZZZ");
                    assertThat(jwt.getExpiresAt()).isNotNull()
                            .isCloseTo(userToExtensionToken.getExpiresAt(), within(1, ChronoUnit.SECONDS));
                }));
    }

    @Test
    void exchange_extensionToApp_withoutActor() throws Exception {
        mockMvc.perform(tokenExchange(retrieveToken(TokenType.USER_TO_EXTENSION), null))
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());
    }

    @Test
    void exchange_extensionToApp_extensionTokenAsSubject() throws Exception {
        mockMvc.perform(tokenExchange(retrieveToken(TokenType.EXTENSION_SERVICE_ACCOUNT), null))
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());
    }

    @Test
    void exchange_extensionToApp_extensionToAppTokenAsSubject() throws Exception {
        mockMvc.perform(tokenExchange(retrieveToken(TokenType.EXTENSION_TO_APP), null))
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());
    }

    @Test
    void exchange_extensionToApp_recursively_success() throws Exception {
        var extensionToAppToken = retrieveToken(TokenType.EXTENSION_TO_APP);

        var gatewayTokenForExtensionToAppToken = createGatewayJwt(jwt -> {
            jwt.claims(Map::clear);

            var splitSubject = extensionToAppToken.getSubject().split("#");
            jwt.issuer(splitSubject[0]);
            jwt.subject(splitSubject[1]);
            jwt.expiresAt(extensionToAppToken.getExpiresAt());
            jwt.claim("act", extensionToAppToken.getClaim("act"));

            jwt.audience(List.of("contentgrid:system:endpoints:authentication"))
                    .claim("context:application:id", "application-id")
                    .claim("context:application:domains", List.of("xyz.contentgrid.test"))
                    .claim("restrict:principal_claims", "enc:YYYY");
        });

        var userToExtensionTokenBis = accessToken(userToExtensionSigningKeys, jwt -> {
            assertThat(jwt.getIssuer()).hasToString("http://extensions.contentgrid.test/authentication/external");
            assertThat(jwt.getSubject()).isEqualTo("http://auth.contentgrid.test/realms/xyz#test-user");
            assertThat(jwt.getClaimAsMap("act")).isEqualTo(Map.of(
                    "iss", "http://extensions.contentgrid.test/authentication/system",
                    "sub", "test-extension"
            ));
            assertThat(jwt.getClaimAsMap("may_act")).isEqualTo(Map.of(
                    "iss", "http://extensions.contentgrid.test/authentication/system",
                    "sub", "ml"
            ));
        }).apply(mockMvc.perform(contentGridTokenGrant(gatewayTokenForExtensionToAppToken)
                        .param("resource", "http://ml-system.test")
                )
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn());

        var extensionTokenBis = accessToken(extensionSigningKeys, jwt -> {}).apply(mockMvc.perform(clientCredentials("machine-learning", "machine-learning-secret"))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn());

        mockMvc.perform(tokenExchange(userToExtensionTokenBis, extensionTokenBis))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(accessToken(extensionToAppSigningKeys, jwt -> {
                    assertThat(jwt.getIssuer()).hasToString("http://extensions.contentgrid.test/authentication/delegated");
                    assertThat(jwt.getSubject()).isEqualTo("http://auth.contentgrid.test/realms/xyz#test-user");
                    assertThat(jwt.getAudience()).containsExactly("contentgrid:application:application-id");
                    assertThat(jwt.getClaimAsMap("act")).isEqualTo(Map.of(
                            "iss", "http://extensions.contentgrid.test/authentication/system",
                            "sub", "ml",
                            "act", Map.of(
                                    "iss", "http://extensions.contentgrid.test/authentication/system",
                                    "sub", "test-extension"
                            )
                    ));
                }))
                .andReturn();
    }

    @Test
    void clientCredentials_extension_success() throws Exception {
        mockMvc.perform(clientCredentials("test-client", "test-client-secret"))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(accessToken(extensionSigningKeys, jwt -> {
                    assertThat(jwt.getIssuer()).hasToString("http://extensions.contentgrid.test/authentication/system");
                    assertThat(jwt.getSubject()).isEqualTo("test-extension");
                    assertThat(jwt.getAudience()).containsExactly("contentgrid:system:extensions");
                }));

    }
}
