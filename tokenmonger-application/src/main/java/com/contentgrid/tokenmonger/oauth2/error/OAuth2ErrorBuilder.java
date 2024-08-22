package com.contentgrid.tokenmonger.oauth2.error;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;
import lombok.experimental.FieldDefaults;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

@Setter
@Accessors(fluent = true)
@FieldDefaults(level = AccessLevel.PRIVATE)
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class OAuth2ErrorBuilder {
    private final String errorCode;

    String parameter = null;

    @Setter(AccessLevel.PRIVATE)
    String parameterValue = null;

    boolean parameterPlural = false;

    @Setter(AccessLevel.NONE)
    List<String> descriptions = new ArrayList<>();

    String uri = null;

    public static OAuth2ErrorBuilder create(String errorCode) {
        return new OAuth2ErrorBuilder(errorCode);
    }

    public static OAuth2ErrorBuilder invalidGrant() {
        return create(OAuth2ErrorCodes.INVALID_GRANT);
    }

    public static OAuth2ErrorBuilder invalidRequest() {
        return create(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    public static OAuth2ErrorBuilder invalidScope() {
        return create(OAuth2ErrorCodes.INVALID_SCOPE);
    }

    public static OAuth2ErrorBuilder invalidTarget() {
        return create("invalid_target")
                .uri("https://www.rfc-editor.org/rfc/rfc8693.html#name-request");
    }

    public OAuth2ErrorBuilder parameter(String key, String value) {
        return parameter(key)
                .parameterValue(value);
    }

    public OAuth2ErrorBuilder description(String description) {
        descriptions.add(description);
        return this;
    }

    public OAuth2ErrorBuilder isRequired() {
        return description("is required");
    }

    public OAuth2ErrorBuilder isSingleValueOnly() {
        return description("may only be supplied once");
    }

    public OAuth2ErrorBuilder mustBeAbsent() {
        return description("must be absent");
    }

    public OAuth2ErrorBuilder allValues(String description) {
        parameterPlural = true;
        return description("must all be "+description);
    }

    public OAuth2Error build() {
        var errorDescriptionBuilder = new StringBuilder();
        if(parameter == null) {
            errorDescriptionBuilder.append("Request ");
        } else {
            errorDescriptionBuilder.append("Parameter '").append(parameter).append("' ");
            if(parameterPlural) {
                errorDescriptionBuilder.append("values ");
            } else if(parameterValue != null) {
                errorDescriptionBuilder.append("value '").append(parameterValue).append("' ");
            }
        }
        errorDescriptionBuilder.append(Objects.requireNonNullElse(convertToString(descriptions), "is invalid"));
        return new OAuth2Error(errorCode, errorDescriptionBuilder.toString(), uri);
    }

    public OAuth2ErrorException buildException() throws OAuth2ErrorException {
        return new OAuth2ErrorException(build());
    }

    private static String convertToString(List<String> list) {
        if (list.isEmpty()) {
            return null;
        } else if (list.size() == 1) {
            return list.get(0);
        } else {
            String result = String.join(", ", list.subList(0, list.size() - 1));
            result += " and " + list.get(list.size() - 1);
            return result;
        }
    }

}
