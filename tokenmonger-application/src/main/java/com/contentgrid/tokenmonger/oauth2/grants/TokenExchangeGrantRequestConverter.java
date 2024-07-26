package com.contentgrid.tokenmonger.oauth2.grants;

import com.contentgrid.tokenmonger.oauth2.grants.GrantUtilities.MultiValueMapWrapper;
import com.contentgrid.tokenmonger.oauth2.token.Token;
import com.contentgrid.tokenmonger.oauth2.token.TokenTypeIdentifier;
import java.util.List;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;

@Component
public class TokenExchangeGrantRequestConverter implements Converter<MultiValueMap<String, String>, TokenExchangeGrantRequest> {

    @Override
    public TokenExchangeGrantRequest convert(MultiValueMap<String, String> source) {
        var wrapper = new MultiValueMapWrapper(source);
        var grantType = GrantType.of(wrapper.requireSingleValue(OAuth2ParameterNames.GRANT_TYPE, new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT)));

        if (!GrantType.TOKEN_EXCHANGE.equals(grantType)) {
            return null;
        }

        var resource = wrapper.getValues(OAuth2ParameterNames.RESOURCE)
                .stream()
                .map(GrantUtilities::convertResourceUri)
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
                        .map(GrantUtilities::convertScope)
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

}
