package com.contentgrid.tokenmonger.web;

import com.contentgrid.tokenmonger.oauth2.error.OAuth2ErrorException;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class OAuthErrorControllerAdvice {
    private static final Map<String, HttpStatusCode> oAuthErrorCodeMap = Map.of(
            OAuth2ErrorCodes.INVALID_REQUEST, HttpStatus.BAD_REQUEST,
            OAuth2ErrorCodes.SERVER_ERROR, HttpStatus.INTERNAL_SERVER_ERROR,
            OAuth2ErrorCodes.TEMPORARILY_UNAVAILABLE, HttpStatus.SERVICE_UNAVAILABLE,
            OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE, HttpStatus.BAD_REQUEST,
            OAuth2ErrorCodes.UNSUPPORTED_TOKEN_TYPE, HttpStatus.BAD_REQUEST,
            OAuth2ErrorCodes.INVALID_SCOPE, HttpStatus.BAD_REQUEST,
            OAuth2ErrorCodes.ACCESS_DENIED, HttpStatus.FORBIDDEN,
            "invalid_target", HttpStatus.BAD_REQUEST
    );
    @ExceptionHandler
    ResponseEntity<OAuthErrorModel> handleOAuthError(OAuth2ErrorException errorException) {
        return ResponseEntity.status(oAuthErrorCodeMap.getOrDefault(errorException.getError().getErrorCode(), HttpStatus.BAD_REQUEST))
                .body(OAuthErrorModel.from(errorException.getError()));
    }

    @Value
    @Builder
    public static class OAuthErrorModel {
        @JsonProperty("error")
        @NonNull
        String errorCode;

        @JsonProperty("error_description")
        @JsonInclude(Include.NON_NULL)
        String description;

        @JsonProperty("error_uri")
        @JsonInclude(Include.NON_NULL)
        String uri;

        public static OAuthErrorModel from(OAuth2Error error) {
            return OAuthErrorModel.builder()
                    .errorCode(error.getErrorCode())
                    .description(error.getDescription())
                    .uri(error.getUri())
                    .build();
        }
    }

}
