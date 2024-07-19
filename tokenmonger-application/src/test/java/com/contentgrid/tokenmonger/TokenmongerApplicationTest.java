package com.contentgrid.tokenmonger;

import java.util.stream.Stream;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@AutoConfigureMockMvc
class TokenmongerApplicationTest extends AbstractTokenmongerApplicationIntegrationTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    void read_jwks_endpoint() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/authentication/system/jwks")
                .header("Host", "extensions.contentgrid.test")
        ).andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().json(eaatSigningKeys.toString()));

        mockMvc.perform(MockMvcRequestBuilders.get("/authentication/external/jwks")
                        .header("Host", "extensions.contentgrid.test")
                ).andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().json(ueatSigningKeys.toString()));

        mockMvc.perform(MockMvcRequestBuilders.get("/authentication/delegated/jwks")
                        .header("Host", "extensions.contentgrid.test")
                ).andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().json(edaatSigningKeys.toString()));
    }


    public static Stream<String> issuerUrls() {
        return Stream.of(
                "authentication/system",
                "authentication/external",
                "authentication/delegated"
        );
    }


    @ParameterizedTest
    @MethodSource("issuerUrls")
    void read_metadata_information_endpoint(String issuer) throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/%s/.well-known/openid-configuration".formatted(issuer))
                .header("Host", "extensions.contentgrid.test")
        ).andExpect(MockMvcResultMatchers.status().is3xxRedirection())
                .andExpect(MockMvcResultMatchers.redirectedUrlTemplate("http://extensions.contentgrid.test/.well-known/oauth-authorization-server/{issuer}", issuer));


        mockMvc.perform(MockMvcRequestBuilders.get("/.well-known/oauth-authorization-server/{issuer}", issuer)
                        .header("Host", "extensions.contentgrid.test")
                )
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.issuer").value(Matchers.endsWith("http://extensions.contentgrid.test/"+issuer)))
                .andExpect(MockMvcResultMatchers.jsonPath("$.jwks_uri").value(Matchers.endsWith("http://extensions.contentgrid.test/"+issuer+"/jwks")));
    }
}