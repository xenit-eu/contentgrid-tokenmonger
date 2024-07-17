package com.contentgrid.tokenmonger.oauth2.grants;

import com.contentgrid.tokenmonger.oauth2.OAuth2ErrorException;
import com.contentgrid.tokenmonger.oauth2.token.Token;
import com.contentgrid.tokenmonger.oauth2.token.TokenTypeIdentifier;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

@Component
public class TokenExchangeGrantRequestConverter implements Converter<MultiValueMap<String, String>, GrantRequest> {

    @Override
    public TokenExchangeGrantRequest convert(MultiValueMap<String, String> source) {
        var wrapper = new MultiValueMapWrapper(source);
        var grantType = GrantType.of(wrapper.requireSingleValue(OAuth2ParameterNames.GRANT_TYPE, new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT)));

        if (!GrantType.TOKEN_EXCHANGE.equals(grantType)) {
            return null;
        }

        var resource = wrapper.getValues(OAuth2ParameterNames.RESOURCE)
                .stream()
                .map(this::convertResourceUri)
                .toList();

        var subjectToken = new Token(
                wrapper.requireSingleValue(OAuth2ParameterNames.SUBJECT_TOKEN, new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST)),
                TokenTypeIdentifier.of(wrapper.requireSingleValue(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST)))
        ) ;

        var actorToken = wrapper.maybeSingleValue(OAuth2ParameterNames.ACTOR_TOKEN, new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST))
                .map(at -> {
                    var actorTokenType = TokenTypeIdentifier.of(wrapper.requireSingleValue(OAuth2ParameterNames.ACTOR_TOKEN_TYPE, new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST)));
                    return new Token(at, actorTokenType);
                });

        // Following https://www.rfc-editor.org/rfc/rfc8693.html#name-request
        return TokenExchangeGrantRequest.builder()
                .grantType(grantType)
                .resource(resource)
                .audience(wrapper.getValues(OAuth2ParameterNames.AUDIENCE))
                .scope(wrapper.maybeSingleValue(OAuth2ParameterNames.SCOPE, new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE))
                        .map(this::convertScope)
                        .orElseGet(List::of)
                )
                .requestedTokenType(wrapper.maybeSingleValue(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE, new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST))
                        .map(TokenTypeIdentifier::of)
                        .orElse(null)
                )
                .subjectToken(subjectToken)
                .actorToken(actorToken.orElse(null))
                .build();
    }

    private List<String> convertScope(String scope) {
        return List.of(StringUtils.delimitedListToStringArray(scope, " "));
    }

    private URI convertResourceUri(String resource) {
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

    @RequiredArgsConstructor
    private static class MultiValueMapWrapper {
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
