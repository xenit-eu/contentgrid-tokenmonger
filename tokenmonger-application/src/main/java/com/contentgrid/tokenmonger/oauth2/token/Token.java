package com.contentgrid.tokenmonger.oauth2.token;

import lombok.NonNull;
import lombok.Value;

@Value
public class Token {
    @NonNull
    String value;
    @NonNull
    TokenTypeIdentifier type;
}
