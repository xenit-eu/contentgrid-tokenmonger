package com.contentgrid.tokenmonger.oauth2.grants;

import java.util.Objects;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Value;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE, staticName = "create")
@Value
public class GrantType {
    public static final GrantType TOKEN_EXCHANGE = GrantType.create("urn:ietf:params:oauth:grant-type:token-exchange");
    public static final GrantType CONTENTGRID_EXTENSION = GrantType.create("https://contentgrid.cloud/oauth2/grant/extension-token");

    private static final GrantType[] REGISTERED_GRANT_TYPES = new GrantType[] {
            TOKEN_EXCHANGE,
            CONTENTGRID_EXTENSION
    };

    @NonNull
    String value;

    public String toString() {
        return value;
    }

    public static GrantType of(@NonNull String grantType) {

        for (GrantType registeredGrantType : REGISTERED_GRANT_TYPES) {
            if(Objects.equals(grantType, registeredGrantType.value)) {
                return registeredGrantType;
            }

        }

        return create(grantType);
    }
}
