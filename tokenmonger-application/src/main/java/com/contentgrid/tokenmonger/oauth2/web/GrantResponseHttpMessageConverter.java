package com.contentgrid.tokenmonger.oauth2.web;

import com.contentgrid.tokenmonger.oauth2.grants.GrantResponse;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

public class GrantResponseHttpMessageConverter implements HttpMessageConverter<GrantResponse> {

    private final MappingJackson2HttpMessageConverter jackson2HttpMessageConverter = new MappingJackson2HttpMessageConverter();

    @Override
    public boolean canRead(Class<?> clazz, MediaType mediaType) {
        return false;
    }

    @Override
    public boolean canWrite(Class<?> clazz, MediaType mediaType) {
        if(GrantResponse.class != clazz) {
            return false;
        }
        return jackson2HttpMessageConverter.canWrite(clazz, mediaType);
    }

    @Override
    public List<MediaType> getSupportedMediaTypes() {
        return jackson2HttpMessageConverter.getSupportedMediaTypes();
    }

    @Override
    public GrantResponse read(Class<? extends GrantResponse> clazz, HttpInputMessage inputMessage)
            throws IOException, HttpMessageNotReadableException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void write(GrantResponse grantResponse, MediaType contentType, HttpOutputMessage outputMessage)
            throws IOException, HttpMessageNotWritableException {

        // https://www.rfc-editor.org/rfc/rfc8693.html#section-2.2.1
        var responseData = new LinkedHashMap<>();
        responseData.put(OAuth2ParameterNames.ACCESS_TOKEN, grantResponse.getAccessToken().getValue());
        responseData.put(OAuth2ParameterNames.ISSUED_TOKEN_TYPE, grantResponse.getAccessToken().getType().getValue());
        responseData.put(OAuth2ParameterNames.TOKEN_TYPE, grantResponse.getTokenType().getValue());
        if(grantResponse.getExpiresAt() != null) {
            responseData.put(OAuth2ParameterNames.EXPIRES_IN, Duration.between(Instant.now(), grantResponse.getExpiresAt()).toSeconds());
        }
        if(grantResponse.getScope() != null && !grantResponse.getScope().isEmpty()) {
            responseData.put(OAuth2ParameterNames.SCOPE, String.join(" ", grantResponse.getScope()));
        }

        if(grantResponse.getRefreshToken() != null) {
            responseData.put(OAuth2ParameterNames.REFRESH_TOKEN, grantResponse.getRefreshToken().getValue());
        }

        jackson2HttpMessageConverter.write(responseData, contentType, outputMessage);
    }
}
