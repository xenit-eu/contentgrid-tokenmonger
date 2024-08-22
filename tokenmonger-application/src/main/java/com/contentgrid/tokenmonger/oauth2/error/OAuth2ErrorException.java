package com.contentgrid.tokenmonger.oauth2.error;

import lombok.Getter;
import lombok.NonNull;
import org.springframework.security.oauth2.core.OAuth2Error;

@Getter
public class OAuth2ErrorException extends RuntimeException {
    private final OAuth2Error error;

    public OAuth2ErrorException(String errorCode) {
        this(new OAuth2Error(errorCode));
    }

    public OAuth2ErrorException(@NonNull OAuth2Error error) {
        this(error, error.toString());
    }

    public OAuth2ErrorException(@NonNull OAuth2Error error, String message) {
        this(error, message, null);
    }

    public OAuth2ErrorException(@NonNull OAuth2Error error, String message, Throwable cause) {
        super(message, cause);
        this.error = error;
    }


    public OAuth2ErrorException(@NonNull OAuth2Error error, Throwable cause) {
        this(error, error.toString(), cause);
    }
}
