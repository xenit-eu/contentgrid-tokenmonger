package com.contentgrid.tokenmonger;

import static org.junit.jupiter.api.Assertions.*;

import com.contentgrid.tokenmonger.IssuerContext.IssuerType;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSetBasedJWKSource;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@SpringBootTest({
        "spring.profiles.active=test"
})
@AutoConfigureMockMvc
class TokenmongerApplicationTest {


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

    @Test
    void read_jwks_endpoints() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/authentication/system/jwks")
                .header("Host", "extensions.contentgrid.test")
        ).andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().json(extensionSigningKeys.toString()));

        mockMvc.perform(MockMvcRequestBuilders.get("/authentication/external/jwks")
                        .header("Host", "extensions.contentgrid.test")
                ).andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().json(userToExtensionSigningKeys.toString()));

        mockMvc.perform(MockMvcRequestBuilders.get("/authentication/delegated/jwks")
                        .header("Host", "extensions.contentgrid.test")
                ).andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().json(extensionToAppSigningKeys.toString()));
    }
}