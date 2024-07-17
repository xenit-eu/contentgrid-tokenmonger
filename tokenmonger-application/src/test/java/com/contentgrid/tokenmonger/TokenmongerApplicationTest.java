package com.contentgrid.tokenmonger;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@AutoConfigureMockMvc
class TokenmongerApplicationTest extends AbstractTokenmongerApplicationIntegrationTest {


    @Autowired
    MockMvc mockMvc;

    @Test
    void read_jwks_endpoints() throws Exception {
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
}