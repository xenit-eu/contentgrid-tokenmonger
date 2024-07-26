package com.contentgrid.tokenmonger.oauth2.grants;

import com.contentgrid.tokenmonger.oauth2.token.Token;
import java.time.Instant;
import java.util.List;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Value;

@Value
@Builder
public class GrantResponse {
    @NonNull
    Token accessToken;
    @NonNull
    TokenType tokenType;

    Instant expiresAt;

    List<String> scope;

    Token refreshToken;

    @RequiredArgsConstructor
    @Getter
    public enum TokenType {
        BEARER("Bearer"),
        N_A("N_A");

        private final String value;
    }
}
