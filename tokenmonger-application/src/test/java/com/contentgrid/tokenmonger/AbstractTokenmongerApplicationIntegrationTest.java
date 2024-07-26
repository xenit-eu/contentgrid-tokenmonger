package com.contentgrid.tokenmonger;

import com.contentgrid.tokenmonger.AbstractTokenmongerApplicationIntegrationTest.TestConfig;
import com.contentgrid.tokenmonger.configuration.CommonConfigurationFactory;
import com.contentgrid.tokenmonger.jwk.source.MockResourcePatternResolver;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest(value = {
        "spring.profiles.active=test"
}, classes = TestConfig.class)
public abstract class AbstractTokenmongerApplicationIntegrationTest {
    static WireMockServer wireMockServer;

    static JWKSet gatewaySigningKeys = new JWKSet(JWKGenerator.createRandomJWK());

    static JWKSet eitSigningKeys = new JWKSet(JWKGenerator.createRandomJWK());

    static JWKSet ueatSigningKeys = new JWKSet(JWKGenerator.createRandomJWK());

    static JWKSet edaatSigningKeys = new JWKSet(JWKGenerator.createRandomJWK());

    static JWKSet eaatSigningKeys = new JWKSet(JWKGenerator.createRandomJWK());

    @TestConfiguration(proxyBeanMethods = false)
    public static class TestConfig {
        @Bean
        @Primary
        public CommonConfigurationFactory mockCommonConfigurationFactory() {
            return new CommonConfigurationFactory(MockResourcePatternResolver.builder()
                    .textResource("file:ueat.json", ueatSigningKeys.getKeys().get(0).toJSONString())
                    .textResource("file:edaat.json", edaatSigningKeys.getKeys().get(0).toJSONString())
                    .textResource("file:eaat.json", eaatSigningKeys.getKeys().get(0).toJSONString())
                    .build());
        }
    }

    @BeforeAll
    static void setupWiremock() {
        wireMockServer = new WireMockServer(new WireMockConfiguration().dynamicPort());
        wireMockServer.start();
        wireMockServer.stubFor(WireMock.get("/gateway-jwks.json")
                .willReturn(WireMock.okJson(gatewaySigningKeys.toString()))
        );
        wireMockServer.stubFor(WireMock.get("/extension-jwks.json")
                .willReturn(WireMock.okJson(eitSigningKeys.toString()))
        );
    }

    @AfterAll
    static void shutdownWiremock() {
        wireMockServer.stop();
    }

    @DynamicPropertySource
    static void configureMockServerPorts(DynamicPropertyRegistry registry) {
        registry.add("contentgrid.tokenmonger.user-application-access.jwk-set-uri", () -> "http://localhost:"+wireMockServer.port()+"/gateway-jwks.json");
        registry.add("contentgrid.tokenmonger.extension-identity.jwk-set-uri", () -> "http://localhost:"+wireMockServer.port()+"/extension-jwks.json");

    }

}
