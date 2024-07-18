package com.contentgrid.tokenmonger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

import com.contentgrid.tokenmonger.IssuerContext.IssuerType;
import com.contentgrid.tokenmonger.oauth2.grants.GrantType;
import com.contentgrid.tokenmonger.test.mockmvc.EncodeToWwwFormRequestPostProcessor;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSetBasedJWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.net.URL;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import lombok.SneakyThrows;
import org.assertj.core.api.ThrowingConsumer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@AutoConfigureMockMvc(printOnlyOnFailure = false)
class TokenMongerApplicationTokenExchangeTests extends AbstractTokenmongerApplicationIntegrationTest {

    @Autowired
    MockMvc mockMvc;


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

    static Jwt createEitJwt() {
        return createEitJwt(jwt -> {

        });
    }

    static Jwt createEitJwt(Consumer<JwtClaimsSet.Builder> configurer) {
        var eitEncoder = new NimbusJwtEncoder(new JWKSetBasedJWKSource<>(new StaticJWKSetSource(eitSigningKeys)));

        var jwtClaimsSetBuilder = JwtClaimsSet.builder()
                .issuer("https://auth.contentgrid.test/realms/extensions")
                .subject("test-extension");

        configurer.accept(jwtClaimsSetBuilder);

        return eitEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetBuilder.build()));
    }

    static AccessTokenJwtMvcResultMatcher userToExtensionToken() {
        return accessToken(ueatSigningKeys, jwt -> {
            assertThat(jwt.getIssuer()).isEqualTo(new URL("http://extensions.contentgrid.test/authentication/external"));
            assertThat(jwt.getSubject()).isEqualTo("http://auth.contentgrid.test/realms/xyz#test-user");
            assertThat(jwt.getAudience()).containsExactly("contentgrid:extension:test-extension");
            assertThat(jwt.getClaimAsString("context:application:id")).isEqualTo("application-id");
            assertThat(jwt.getClaimAsStringList("context:application:domains")).isEqualTo(List.of("xyz.contentgrid.test"));
            assertThat(jwt.getClaimAsString("restrict:principal_claims")).isEqualTo("enc:ZZZZ");
            assertThat(jwt.getExpiresAt()).isNotNull()
                    .isBeforeOrEqualTo(Instant.now().plus(5, ChronoUnit.MINUTES));
            assertThat(jwt.getClaimAsMap("may_act")).isEqualTo(Map.of(
                    "iss", "https://auth.contentgrid.test/realms/extensions",
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
                .param("grant_type", GrantType.CONTENTGRID_EXTENSION.getValue())
                .with(new EncodeToWwwFormRequestPostProcessor());
    }

    static MockHttpServletRequestBuilder tokenExchange(String uri) {
        return MockMvcRequestBuilders.post(uri)
                .header("Host", "extensions.contentgrid.test")
                .param("grant_type", AuthorizationGrantType.TOKEN_EXCHANGE.getValue())
                .with(new EncodeToWwwFormRequestPostProcessor());
    }

    static MockHttpServletRequestBuilder tokenExchange(String uri, Jwt subjectToken, Jwt actorToken) {
        var requestBuilder = tokenExchange(uri);
        if(subjectToken != null) {
                requestBuilder  = requestBuilder.param("subject_token", subjectToken.getTokenValue())
                    .param("subject_token_type", "urn:ietf:params:oauth:token-type:access_token");
        }
        if(actorToken != null) {
                requestBuilder = requestBuilder.param("actor_token", actorToken.getTokenValue())
                    .param("actor_token_type", "urn:ietf:params:oauth:token-type:access_token");
        }
        return requestBuilder.param("requested_token_type", "urn:ietf:params:oauth:token-type:access_token");
    }

    static MockHttpServletRequestBuilder clientCredentials(String clientId, String clientSecret) {
        return MockMvcRequestBuilders.post("/authentication/system/token")
                .header("Host", "extensions.contentgrid.test")
                .param("grant_type", AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                .param("client_id", clientId)
                .param("client_secret", clientSecret);
    }

    private Jwt retrieveToken(IssuerType tokenType) throws Exception {
        return switch (tokenType) {
            case USER_APPLICATION_ACCESS_TOKEN -> createGatewayJwt();
            case USER_EXTENSION_ACCESS_TOKEN -> accessToken(ueatSigningKeys, jwt -> {}).apply(
                    mockMvc.perform(contentGridTokenGrant(retrieveToken(IssuerType.USER_APPLICATION_ACCESS_TOKEN))
                            .param("resource", "http://extension-system.test/xyz")
                    ).andExpect(MockMvcResultMatchers.status().isOk()).andReturn());
            case EXTENSION_IDENTITY_TOKEN -> createEitJwt();
            case EXTENSION_APPLICATION_ACCESS_TOKEN -> accessToken(eaatSigningKeys, jwt -> {}).apply(mockMvc.perform(tokenExchange("/authentication/system/token", retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN), null)).andExpect(MockMvcResultMatchers.status().isOk()).andReturn());
            case EXTENSION_DELEGATED_APPLICATION_ACCESS_TOKEN -> accessToken(edaatSigningKeys, jwt -> {}).apply(mockMvc.perform(tokenExchange("/authentication/delegated/token", retrieveToken(IssuerType.USER_EXTENSION_ACCESS_TOKEN), retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN))).andExpect(MockMvcResultMatchers.status().isOk()).andReturn());
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
                .andExpect(accessToken(ueatSigningKeys, jwt -> {
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
                .andExpect(accessToken(ueatSigningKeys, jwt -> {
                    assertThat(jwt.getExpiresAt()).isCloseTo(Instant.now().plus(5, ChronoUnit.MINUTES), within(30, ChronoUnit.SECONDS));
                }));
    }


    @Test
    void jwks_userToExtension() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/authentication/external/jwks")
                        .header("Host", "extensions.contentgrid.test")
                )
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().json(ueatSigningKeys.toString(true)));
    }


    @Test
    void exchange_extensionToApp_success() throws Exception {
        var userToExtensionToken = retrieveToken(IssuerType.USER_EXTENSION_ACCESS_TOKEN);
        mockMvc.perform(tokenExchange("/authentication/delegated/token", userToExtensionToken, retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(accessToken(edaatSigningKeys, jwt -> {
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
        mockMvc.perform(tokenExchange("/authentication/delegated/token", retrieveToken(IssuerType.USER_EXTENSION_ACCESS_TOKEN), null))
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());
    }

    @Test
    void exchange_extensionToApp_extensionTokenAsSubject() throws Exception {
        mockMvc.perform(tokenExchange("/authentication/delegated/token", retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN), null))
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());
    }

    @Test
    void exchange_extensionToApp_extensionToAppTokenAsSubject() throws Exception {
        mockMvc.perform(tokenExchange("/authentication/delegated/token", retrieveToken(IssuerType.EXTENSION_DELEGATED_APPLICATION_ACCESS_TOKEN), null))
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());
    }

    @Test
    void exchange_extensionToApp_recursively_success() throws Exception {
        var extensionToAppToken = retrieveToken(IssuerType.EXTENSION_DELEGATED_APPLICATION_ACCESS_TOKEN);

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

        var userToExtensionTokenBis = accessToken(ueatSigningKeys, jwt -> {
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

        var extensionTokenBis = createEitJwt(jwt -> {
            jwt.subject("ml");
        });

        mockMvc.perform(tokenExchange("/authentication/delegated/token", userToExtensionTokenBis, extensionTokenBis))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(accessToken(edaatSigningKeys, jwt -> {
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
    void exchange_extensionApplicationAccessToken_success() throws Exception {
        var eit = retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN);

        mockMvc.perform(tokenExchange("/authentication/system/token", eit, null)
                        .param("resource", "https://test1.app.contentgrid.example/xyz")
                )
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(accessToken(eaatSigningKeys, jwt -> {
                    assertThat(jwt.getIssuer()).hasToString("http://extensions.contentgrid.test/authentication/system");
                    assertThat(jwt.getSubject()).isEqualTo("test-extension");
                    assertThat(jwt.getAudience()).containsExactly("contentgrid:application:test1");
                }));
    }

    @Test
    void exchange_extensionApplicationAccessToken_missingResource() throws Exception {
        var eit = retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN);

        mockMvc.perform(tokenExchange("/authentication/system/token", eit, null))
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());
    }

    @Test
    void exchange_extensionApplicationAccessToken_unknownApplication() throws Exception {
        var eit = retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN);

        mockMvc.perform(tokenExchange("/authentication/system/token", eit, null)
                        .param("resource", "https://unknown-app.invalid"))
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());

    }
}
