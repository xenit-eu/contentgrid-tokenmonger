package com.contentgrid.tokenmonger.oauth2.grants;

import com.contentgrid.tokenmonger.oauth2.OAuth2ErrorException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.UtilityClass;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

@UtilityClass
public class GrantUtilities {

    static URI convertResourceUri(String resource) {
        try {
            var uri = new URI(resource);
            if(!uri.isAbsolute()) {
                throw new OAuth2ErrorException(createInvalidResourceError("The 'resource' parameter must be an absolute URI"));
            }
            if(uri.getRawFragment() != null) {
                throw new OAuth2ErrorException(createInvalidResourceError("The 'resource' parameter must not contain a fragment component"));
            }
            return uri;
        } catch (URISyntaxException e) {
            throw new OAuth2ErrorException(createInvalidResourceError("The 'resource' parameter must be a valid URI"));
        }
    }

    private static OAuth2Error createInvalidResourceError(String description) {
        return new OAuth2Error("invalid_target", description, "https://www.rfc-editor.org/rfc/rfc8693.html#name-request");
    }

    static List<String> convertScope(String scope) {
        return List.of(StringUtils.delimitedListToStringArray(scope, " "));
    }

    @RequiredArgsConstructor
    static class MultiValueMapWrapper {
        private final MultiValueMap<String, String> values;

        @NonNull
        public String requireSingleValue(@NonNull String key, @NonNull OAuth2Error error) {
            var value = values.get(key);
            if(value == null || value.isEmpty()) {
                throw new OAuth2ErrorException(error, "Parameter '%s' is missing".formatted(key));
            } else if(value.size() > 1) {
                throw new OAuth2ErrorException(error, "Parameter '%s' may only be supplied once".formatted(key));
            }
            return value.get(0);
        }

        public Optional<String> maybeSingleValue(@NonNull String key, @NonNull OAuth2Error error) {
            var value = values.get(key);

            if(value == null || value.isEmpty()) {
                return Optional.empty();
            }
            if(value.size() > 1) {
                throw new OAuth2ErrorException(error, "Parameter '%s' may only be supplied once".formatted(key));
            }

            return Optional.of(value.get(0));
        }

        public List<String> getValues(@NonNull String key) {
            return values.getOrDefault(key, List.of());
        }

    }
}
