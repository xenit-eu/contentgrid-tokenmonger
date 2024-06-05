package com.contentgrid.tokenmonger;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.assertj.core.api.ThrowingConsumer;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;

@RequiredArgsConstructor
public class AccessTokenJwtMvcResultMatcher implements ResultMatcher {
    private final JwtDecoder jwtDecoder;
    private final ThrowingConsumer<? super Jwt> jwtMatcher;

    @Override
    public void match(MvcResult result) throws Exception {
        var objectMapper = new ObjectMapper();
        var tokenResponse = objectMapper.readTree(result.getResponse().getContentAsByteArray());

        assertThat(tokenResponse.get("access_token"))
                .as("returned access token")
                .isNotNull();

        var jwt = jwtDecoder.decode(tokenResponse.get("access_token").asText());

        assertThat(jwt).satisfies(jwtMatcher);

    }
}
