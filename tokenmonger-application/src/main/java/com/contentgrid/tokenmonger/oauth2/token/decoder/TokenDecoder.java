package com.contentgrid.tokenmonger.oauth2.token.decoder;

import com.contentgrid.tokenmonger.oauth2.token.Token;

public interface TokenDecoder<T> {
    boolean supports(Token token);

    T decode(Token token);
}
