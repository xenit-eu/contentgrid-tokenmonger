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
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Stream;
import lombok.SneakyThrows;
import org.assertj.core.api.ThrowingConsumer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
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

@AutoConfigureMockMvc
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
                .claim("context:application:id", "test1")
                .claim("context:application:domains", List.of("test1.app.contentgrid.example", "my-domain.app.contentgrid.example"))
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
                .subject("test-extension")
                .audience(List.of("tokenmonger"));

        configurer.accept(jwtClaimsSetBuilder);

        return eitEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetBuilder.build()));
    }

    static AccessTokenJwtMvcResultMatcher userToExtensionToken() {
        return accessToken(ueatSigningKeys, jwt -> {
            assertThat(jwt.getIssuer()).isEqualTo(new URL("http://extensions.contentgrid.test/authentication/external"));
            assertThat(jwt.getSubject()).isEqualTo("http://auth.contentgrid.test/realms/xyz#test-user");
            assertThat(jwt.getAudience()).containsExactly("contentgrid:extension:test-extension");
            assertThat(jwt.getClaimAsString("context:application:id")).isEqualTo("test1");
            assertThat(jwt.getClaimAsStringList("context:application:domains")).isEqualTo(List.of("test1.app.contentgrid.example", "my-domain.app.contentgrid.example"));
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

    private Jwt retrieveToken(IssuerType tokenType) throws Exception {
        return switch (tokenType) {
            case USER_APPLICATION_ACCESS_TOKEN -> createGatewayJwt();
            case USER_EXTENSION_ACCESS_TOKEN -> accessToken(ueatSigningKeys, jwt -> {}).apply(
                    mockMvc.perform(contentGridTokenGrant(retrieveToken(IssuerType.USER_APPLICATION_ACCESS_TOKEN))
                            .param("resource", "http://extension-system.test/xyz")
                    ).andExpect(MockMvcResultMatchers.status().isOk()).andReturn());
            case EXTENSION_IDENTITY_TOKEN -> createEitJwt();
            case EXTENSION_APPLICATION_ACCESS_TOKEN -> accessToken(eaatSigningKeys, jwt -> {}).apply(mockMvc.perform(tokenExchange("/authentication/system/token", retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN), null)
                    .param("resource", "http://test1.app.contentgrid.example/")
            ).andExpect(MockMvcResultMatchers.status().isOk()).andReturn());
            case EXTENSION_DELEGATED_APPLICATION_ACCESS_TOKEN -> accessToken(edaatSigningKeys, jwt -> {}).apply(mockMvc.perform(tokenExchange("/authentication/delegated/token", retrieveToken(IssuerType.USER_EXTENSION_ACCESS_TOKEN), retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN))).andExpect(MockMvcResultMatchers.status().isOk()).andReturn());
        };
    }

    @Nested
    class UserExtensionAccessToken {

        @Test
        void exchange_success() throws Exception {
            var gatewayToken = createGatewayJwt();

            mockMvc.perform(contentGridTokenGrant(gatewayToken)
                            .param("resource", "http://extension-system.test/xyz")
                    )
                    .andExpect(MockMvcResultMatchers.status().isOk())
                    .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    .andExpect(userToExtensionToken());
        }

        @Test
        void exchange_multipleResources_singleExtension_success() throws Exception {
            var gatewayToken = createGatewayJwt();

            mockMvc.perform(contentGridTokenGrant(gatewayToken)
                            .param("resource", "http://extension-system.test/xyz")
                            .param("resource", "http://extension-system.test/")
                    )
                    .andExpect(MockMvcResultMatchers.status().isOk())
                    .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    .andExpect(userToExtensionToken());
        }

        @Test
        void exchange_multipleResources_multipleExtension_failure() throws Exception {
            var gatewayToken = createGatewayJwt();

            mockMvc.perform(contentGridTokenGrant(gatewayToken)
                            .param("resource", "http://extension-system.test/xyz")
                            .param("resource", "http://ml-system.test/")
                    )
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_request"));
        }

        @Test
        void exchange_unknownResource() throws Exception {
            var gatewayToken = createGatewayJwt();

            mockMvc.perform(contentGridTokenGrant(gatewayToken)
                            .param("resource", "http://unknown-extension.invalid/")
                    )
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_request"));
        }

        @Test
        void exchange_invalidAudience() throws Exception {
            var gatewayToken = createGatewayJwt(jwt -> jwt.audience(List.of("invalid_audience")));

            mockMvc.perform(contentGridTokenGrant(gatewayToken)
                            .param("resource", "http://extension-system.test/xyz")
                    )
                    .andExpect(MockMvcResultMatchers.status().isUnauthorized());
        }

        @Test
        void exchange_expiredToken() throws Exception {
            var gatewayToken = createGatewayJwt(jwt -> jwt.expiresAt(Instant.now().minus(1, ChronoUnit.MINUTES)));

            mockMvc.perform(contentGridTokenGrant(gatewayToken)
                            .param("resource", "http://extension-system.test/xyz")
                    )
                    .andExpect(MockMvcResultMatchers.status().isUnauthorized());
        }

        @Test
        void exchange_shortlyExpiringToken() throws Exception {
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
        void exchange_longExpiringToken() throws Exception {
            var expiryTime = Instant.now().plus(10, ChronoUnit.HOURS);
            var gatewayToken = createGatewayJwt(jwt -> jwt.expiresAt(expiryTime));

            mockMvc.perform(contentGridTokenGrant(gatewayToken)
                            .param("resource", "http://extension-system.test/xyz")
                    )
                    .andExpect(MockMvcResultMatchers.status().isOk())
                    .andExpect(accessToken(ueatSigningKeys, jwt -> {
                        assertThat(jwt.getExpiresAt()).isCloseTo(Instant.now().plus(5, ChronoUnit.MINUTES),
                                within(30, ChronoUnit.SECONDS));
                    }));
        }

    }

    @Nested
    class ExtensionDelegatedApplicationAccessToken {

        @Test
        void exchange_success() throws Exception {
            var userToExtensionToken = retrieveToken(IssuerType.USER_EXTENSION_ACCESS_TOKEN);
            mockMvc.perform(tokenExchange("/authentication/delegated/token", userToExtensionToken,
                            retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN)))
                    .andExpect(MockMvcResultMatchers.status().isOk())
                    .andExpect(accessToken(edaatSigningKeys, jwt -> {
                        assertThat(jwt.getIssuer()).hasToString(
                                "http://extensions.contentgrid.test/authentication/delegated");
                        assertThat(jwt.getSubject()).isEqualTo("http://auth.contentgrid.test/realms/xyz#test-user");
                        assertThat(jwt.getClaimAsMap("act"))
                                .containsEntry("iss", "https://auth.contentgrid.test/realms/extensions")
                                .containsEntry("sub", "test-extension");

                        assertThat(jwt.getAudience()).containsExactly("contentgrid:application:test1");
                        assertThat(jwt.getClaimAsString("restrict:principal_claims")).isEqualTo("enc:ZZZZ");
                        assertThat(jwt.getExpiresAt()).isNotNull()
                                .isCloseTo(userToExtensionToken.getExpiresAt(), within(1, ChronoUnit.SECONDS));
                        assertThat(jwt.hasClaim("context:application:resource")).isFalse();
                    }));
        }

        @Test
        void exchange_resource_inApp_success() throws Exception {
            var userToExtensionToken = retrieveToken(IssuerType.USER_EXTENSION_ACCESS_TOKEN);
            mockMvc.perform(tokenExchange("/authentication/delegated/token", userToExtensionToken,
                            retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN))
                            .param("resource", "http://test1.app.contentgrid.example/xyz")
                    )
                    .andExpect(MockMvcResultMatchers.status().isOk())
                    .andExpect(accessToken(edaatSigningKeys, jwt -> {
                        assertThat(jwt.getAudience()).containsExactly("contentgrid:application:test1");
                        assertThat(jwt.getClaimAsStringList("context:application:resource")).containsExactly("/xyz");
                    }));
        }


        @Test
        void exchange_multipleResources_inApp_success() throws Exception {
            var userToExtensionToken = retrieveToken(IssuerType.USER_EXTENSION_ACCESS_TOKEN);
            mockMvc.perform(tokenExchange("/authentication/delegated/token", userToExtensionToken,
                            retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN))
                            .param("resource", "http://test1.app.contentgrid.example/xyz")
                            .param("resource", "http://my-domain.app.contentgrid.example/fff?a=c")
                    )
                    .andExpect(MockMvcResultMatchers.status().isOk())
                    .andExpect(accessToken(edaatSigningKeys, jwt -> {
                        assertThat(jwt.getAudience()).containsExactly("contentgrid:application:test1");
                        assertThat(jwt.getClaimAsStringList("context:application:resource")).containsExactly("/xyz", "/fff?a=c");
                    }));
        }

        @Test
        void exchange_resource_otherApp_failure() throws Exception {
            var userToExtensionToken = retrieveToken(IssuerType.USER_EXTENSION_ACCESS_TOKEN);
            mockMvc.perform(tokenExchange("/authentication/delegated/token", userToExtensionToken,
                            retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN))
                            .param("resource", "http://test2.app.contentgrid.test/xyz")
                    )
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_target"))
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error_description").value("Requested resource is not an allowed host (my-domain.app.contentgrid.example, test1.app.contentgrid.example)"))
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error_uri").exists());
        }

        @Test
        void exchange_resource_unknownApp_failure() throws Exception {
            var userToExtensionToken = retrieveToken(IssuerType.USER_EXTENSION_ACCESS_TOKEN);
            mockMvc.perform(tokenExchange("/authentication/delegated/token", userToExtensionToken,
                            retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN))
                            .param("resource", "http://not-an-app.test/xyz")
                    )
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_target"))
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error_description").value("Requested resource is not an allowed host (my-domain.app.contentgrid.example, test1.app.contentgrid.example)"))
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error_uri").exists());
        }
        @Test
        void exchange_withoutActor() throws Exception {
            mockMvc.perform(tokenExchange("/authentication/delegated/token",
                            retrieveToken(IssuerType.USER_EXTENSION_ACCESS_TOKEN), null))
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_request"))
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error_description").value("Actor token is required"))
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error_uri").exists());
        }

        @Test
        void exchange_missingSubject() throws Exception {
            mockMvc.perform(tokenExchange("/authentication/delegated/token", null,
                    retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN)))
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_request"));
        }

        public static Stream<IssuerType> exchange_invalidSubjectToken() {
            return Arrays.stream(IssuerType.values())
                    .filter(Predicate.not(Predicate.isEqual(IssuerType.USER_EXTENSION_ACCESS_TOKEN)));
        }

        @ParameterizedTest
        @MethodSource
        void exchange_invalidSubjectToken(IssuerType issuerType) throws Exception {
            mockMvc.perform(
                            tokenExchange("/authentication/delegated/token", retrieveToken(issuerType),
                                    retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN)))
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_request"));
        }

        public static Stream<IssuerType> exchange_invalidActorToken() {
            return Arrays.stream(IssuerType.values())
                    .filter(Predicate.not(Predicate.isEqual(IssuerType.EXTENSION_IDENTITY_TOKEN)));
        }

        @ParameterizedTest
        @MethodSource
        void exchange_invalidActorToken(IssuerType issuerType) throws Exception {
            mockMvc.perform(
                            tokenExchange("/authentication/delegated/token", retrieveToken(IssuerType.USER_EXTENSION_ACCESS_TOKEN),
                                    retrieveToken(issuerType)))
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_request"));
        }

        @Test
        void exchange_scope() throws Exception {
            var userToExtensionToken = retrieveToken(IssuerType.USER_EXTENSION_ACCESS_TOKEN);
            mockMvc.perform(tokenExchange("/authentication/delegated/token", userToExtensionToken,
                            retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN))
                            .param("scope", "test")
                    )
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_request"));
        }

        @Test
        void exchange_audience() throws Exception {
            var userToExtensionToken = retrieveToken(IssuerType.USER_EXTENSION_ACCESS_TOKEN);
            mockMvc.perform(tokenExchange("/authentication/delegated/token", userToExtensionToken,
                            retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN))
                            .param("audience", "test")
                    )
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_request"));
        }

        @Test
        void exchange_wrongActor_sub() throws Exception {
            var userToExtensionToken = retrieveToken(IssuerType.USER_EXTENSION_ACCESS_TOKEN);
            var extensionIdentityToken = createEitJwt(jwt -> {
                jwt.subject("other-extension");
            });
            mockMvc.perform(tokenExchange("/authentication/delegated/token", userToExtensionToken,
                            extensionIdentityToken))
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_request"))
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error_description").value("Actor is not allowed to act on behalf of the subject"))
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error_uri").exists());
        }

        @Test
        void exchange_wrongActor_iss() throws Exception {
            var userToExtensionToken = retrieveToken(IssuerType.USER_EXTENSION_ACCESS_TOKEN);
            var extensionIdentityToken = createEitJwt(jwt -> {
                jwt.issuer("http://other-issuer.example/zzzz");
            });
            mockMvc.perform(tokenExchange("/authentication/delegated/token", userToExtensionToken,
                            extensionIdentityToken))
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_request"));
        }

        @Test
        void exchange_recursively_success() throws Exception {
            var extensionToAppToken = retrieveToken(IssuerType.EXTENSION_DELEGATED_APPLICATION_ACCESS_TOKEN);

            var gatewayTokenForExtensionToAppToken = createGatewayJwt(jwt -> {
                jwt.claims(Map::clear);

                var splitSubject = extensionToAppToken.getSubject().split("#");
                jwt.issuer(splitSubject[0]);
                jwt.subject(splitSubject[1]);
                jwt.expiresAt(extensionToAppToken.getExpiresAt());
                jwt.claim("act", extensionToAppToken.getClaim("act"));

                jwt.audience(List.of("contentgrid:system:endpoints:authentication"))
                        .claim("context:application:id", "test1")
                        .claim("context:application:domains", List.of("test1.app.contentgrid.example", "my-domain.app.contentgrid.example"))
                        .claim("restrict:principal_claims", "enc:YYYY");
            });

            var userToExtensionTokenBis = accessToken(ueatSigningKeys, jwt -> {
                assertThat(jwt.getIssuer()).hasToString("http://extensions.contentgrid.test/authentication/external");
                assertThat(jwt.getSubject()).isEqualTo("http://auth.contentgrid.test/realms/xyz#test-user");
                assertThat(jwt.getClaimAsMap("act")).isEqualTo(Map.of(
                        "iss", "https://auth.contentgrid.test/realms/extensions",
                        "sub", "test-extension"
                ));
                assertThat(jwt.getClaimAsMap("may_act")).isEqualTo(Map.of(
                        "iss", "https://auth.contentgrid.test/realms/extensions",
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

            mockMvc.perform(
                            tokenExchange("/authentication/delegated/token", userToExtensionTokenBis, extensionTokenBis))
                    .andExpect(MockMvcResultMatchers.status().isOk())
                    .andExpect(accessToken(edaatSigningKeys, jwt -> {
                        assertThat(jwt.getIssuer()).hasToString(
                                "http://extensions.contentgrid.test/authentication/delegated");
                        assertThat(jwt.getSubject()).isEqualTo("http://auth.contentgrid.test/realms/xyz#test-user");
                        assertThat(jwt.getAudience()).containsExactly("contentgrid:application:test1");
                        assertThat(jwt.getClaimAsMap("act")).isEqualTo(Map.of(
                                "iss", "https://auth.contentgrid.test/realms/extensions",
                                "sub", "ml",
                                "act", Map.of(
                                        "iss", "https://auth.contentgrid.test/realms/extensions",
                                        "sub", "test-extension"
                                )
                        ));
                    }))
                    .andReturn();
        }
    }

    @Nested
    class ExtensionApplicationAccessToken {

        @Test
        void exchange_success() throws Exception {
            var eit = retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN);

            mockMvc.perform(tokenExchange("/authentication/system/token", eit, null)
                            .param("resource", "https://test1.app.contentgrid.example/xyz")
                    )
                    .andExpect(MockMvcResultMatchers.status().isOk())
                    .andExpect(accessToken(eaatSigningKeys, jwt -> {
                        assertThat(jwt.getIssuer()).hasToString(
                                "http://extensions.contentgrid.test/authentication/system");
                        assertThat(jwt.getSubject()).isEqualTo("test-extension");
                        assertThat(jwt.getAudience()).containsExactly("contentgrid:application:test1");
                        assertThat(jwt.getClaimAsStringList("context:application:resource")).containsExactly("/xyz");
                    }));
        }

        @Test
        void exchange_multipleResource_singleApp_success() throws Exception {
            var eit = retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN);

            mockMvc.perform(tokenExchange("/authentication/system/token", eit, null)
                            .param("resource", "https://test1.app.contentgrid.example/xyz")
                            .param("resource", "https://my-domain.app.contentgrid.example/fff?a=b")
                    )
                    .andExpect(MockMvcResultMatchers.status().isOk())
                    .andExpect(accessToken(eaatSigningKeys, jwt -> {
                        assertThat(jwt.getIssuer()).hasToString(
                                "http://extensions.contentgrid.test/authentication/system");
                        assertThat(jwt.getSubject()).isEqualTo("test-extension");
                        assertThat(jwt.getAudience()).containsExactly("contentgrid:application:test1");
                        assertThat(jwt.getClaimAsStringList("context:application:resource")).containsExactly("/xyz", "/fff?a=b");
                    }));
        }

        @Test
        void exchange_invalidAudience() throws Exception {
            var eit = createEitJwt(builder -> builder.audience(List.of("invalid_audience")));
            mockMvc.perform(tokenExchange("/authentication/system/token", eit, null)
                            .param("resource", "https://test1.app.contentgrid.example/xyz")
                    )
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_request"));
        }

        @Test
        void exchange_scope() throws Exception {
            var eit = retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN);
            mockMvc.perform(tokenExchange("/authentication/system/token", eit, null)
                            .param("scope", "test")
                    )
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_request"));
        }

        @Test
        void exchange_audience() throws Exception {
            var eit = retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN);
            mockMvc.perform(tokenExchange("/authentication/system/token", eit, null)
                            .param("audience", "test")
                    )
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_request"));
        }

        public static Stream<IssuerType> exchange_invalidSubjectToken() {
            return Arrays.stream(IssuerType.values())
                    .filter(Predicate.not(Predicate.isEqual(IssuerType.EXTENSION_IDENTITY_TOKEN)));
        }

        @ParameterizedTest
        @MethodSource
        void exchange_invalidSubjectToken(IssuerType issuerType) throws Exception {
            mockMvc.perform(tokenExchange("/authentication/system/token", retrieveToken(issuerType), null))
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_request"));
        }

        public static Stream<IssuerType> exchange_invalidActorToken() {
            return Arrays.stream(IssuerType.values());
        }

        @ParameterizedTest
        @MethodSource
        void exchange_invalidActorToken(IssuerType issuerType) throws Exception {
            mockMvc.perform(
                            tokenExchange("/authentication/system/token", retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN),
                                    retrieveToken(issuerType)))
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_request"));
        }


        @Test
        void exchange_missingResource() throws Exception {
            var eit = retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN);

            mockMvc.perform(tokenExchange("/authentication/system/token", eit, null))
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_request"));
        }

        @Test
        void exchange_multipleResource_multipleApps() throws Exception {
            var eit = retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN);

            mockMvc.perform(tokenExchange("/authentication/system/token", eit, null)
                            .param("resource", "https://test1.app.contentgrid.example/xyz")
                            .param("resource", "https://test2.app.contentgrid.example/fff?a=b")
                    )
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_request"));
        }

        @Test
        void exchange_unknownApplication() throws Exception {
            var eit = retrieveToken(IssuerType.EXTENSION_IDENTITY_TOKEN);

            mockMvc.perform(tokenExchange("/authentication/system/token", eit, null)
                            .param("resource", "https://unknown-app.invalid"))
                    .andExpect(MockMvcResultMatchers.status().isBadRequest())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.error").value("invalid_request"));

        }
    }
}
