package com.contentgrid.tokenmonger.oauth2.token;

import java.util.Objects;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Value;


@RequiredArgsConstructor(access = AccessLevel.PRIVATE, staticName = "create")
@Value
public class TokenTypeIdentifier {
    public static final TokenTypeIdentifier ACCESS_TOKEN = TokenTypeIdentifier.create("urn:ietf:params:oauth:token-type:access_token");
    public static final TokenTypeIdentifier REFRESH_TOKEN = TokenTypeIdentifier.create("urn:ietf:params:oauth:token-type:refresh_token");
    public static final TokenTypeIdentifier ID_TOKEN = TokenTypeIdentifier.create("urn:ietf:params:oauth:token-type:id_token");
    public static final TokenTypeIdentifier JWT = TokenTypeIdentifier.create("urn:ietf:params:oauth:token-type:jwt");

    private static final TokenTypeIdentifier[] REGISTERED_IDENTIFIERS = new TokenTypeIdentifier[] {
            ACCESS_TOKEN,
            REFRESH_TOKEN,
            ID_TOKEN,
            JWT
    };

    @NonNull
    String value;

    @Override
    public String toString() {
        return value;
    }

    public static TokenTypeIdentifier of(@NonNull String identifier) {

        for (TokenTypeIdentifier registeredIdentifier : REGISTERED_IDENTIFIERS) {
            if(Objects.equals(identifier, registeredIdentifier.value)) {
                return registeredIdentifier;
            }

        }

        return create(identifier);
    }

}
