package com.contentgrid.tokenmonger.oauth2.grants;

import java.util.List;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;

@Component
public class ContentgridExtensionTokenGrantRequestConverter implements Converter<MultiValueMap<String, String>, ContentgridExtensionTokenGrantRequest> {

    @Override
    public ContentgridExtensionTokenGrantRequest convert(MultiValueMap<String, String> source) {
        var wrapper = new GrantUtilities.MultiValueMapWrapper(source);
        var grantType = GrantType.of(wrapper.requireSingleValue(OAuth2ParameterNames.GRANT_TYPE, new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT)));

        if (!GrantType.CONTENTGRID_EXTENSION.equals(grantType)) {
            return null;
        }

        var resource = wrapper.getValues(OAuth2ParameterNames.RESOURCE)
                .stream()
                .map(GrantUtilities::convertResourceUri)
                .toList();

        return ContentgridExtensionTokenGrantRequest.builder()
                .grantType(grantType)
                .resource(resource)
                .scope(wrapper.maybeSingleValue(OAuth2ParameterNames.SCOPE, new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE))
                        .map(GrantUtilities::convertScope)
                        .orElseGet(List::of)
                )
                .build();
    }

}
