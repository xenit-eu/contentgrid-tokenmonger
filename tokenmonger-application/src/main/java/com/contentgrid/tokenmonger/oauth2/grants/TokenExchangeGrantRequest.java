package com.contentgrid.tokenmonger.oauth2.grants;

import com.contentgrid.tokenmonger.oauth2.token.Token;
import com.contentgrid.tokenmonger.oauth2.token.TokenTypeIdentifier;
import java.net.URI;
import java.util.List;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Builder(access = AccessLevel.PACKAGE)
@Value
public class TokenExchangeGrantRequest implements GrantRequest, GrantRequest.HasScope {
    @NonNull
    GrantType grantType;

    TokenTypeIdentifier requestedTokenType;

    @NonNull
    Token subjectToken;

    Token actorToken;

    @NonNull
    List<URI> resource;

    @NonNull
    List<String> audience;

    @NonNull
    List<String> scope;

}
