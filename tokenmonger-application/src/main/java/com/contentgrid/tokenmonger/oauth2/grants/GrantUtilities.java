package com.contentgrid.tokenmonger.oauth2.grants;

import com.contentgrid.tokenmonger.oauth2.error.OAuth2ErrorBuilder;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.UtilityClass;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

@UtilityClass
public class GrantUtilities {

    static URI convertResourceUri(String resource) {
        var errorBuilder = OAuth2ErrorBuilder.invalidTarget().parameter("resource");
        try {
            var uri = new URI(resource);
            if(!uri.isAbsolute()) {
                throw errorBuilder.description("must be an absolute URI").buildException();
            }
            if(uri.getRawFragment() != null) {
                throw errorBuilder.description("must not contain a fragment component").buildException();
            }
            return uri;
        } catch (URISyntaxException e) {
            throw errorBuilder.description("must be a valid URI").buildException();
        }
    }

    static List<String> convertScope(String scope) {
        return List.of(StringUtils.delimitedListToStringArray(scope, " "));
    }

    @RequiredArgsConstructor
    static class MultiValueMapWrapper {
        private final MultiValueMap<String, String> values;

        @NonNull
        public String requireSingleValue(@NonNull String key, @NonNull OAuth2ErrorBuilder error) {
            var value = values.get(key);
            if(value == null || value.isEmpty()) {
                throw error.parameter(key).isRequired().buildException();
            } else if(value.size() > 1) {
                throw error.parameter(key).isSingleValueOnly().buildException();
            }
            return value.get(0);
        }

        public Optional<String> maybeSingleValue(@NonNull String key, @NonNull OAuth2ErrorBuilder error) {
            var value = values.get(key);

            if(value == null || value.isEmpty()) {
                return Optional.empty();
            }
            if(value.size() > 1) {
                throw error.parameter(key).isSingleValueOnly().buildException();
            }

            return Optional.of(value.get(0));
        }

        public List<String> getValues(@NonNull String key) {
            return values.getOrDefault(key, List.of());
        }

    }
}
