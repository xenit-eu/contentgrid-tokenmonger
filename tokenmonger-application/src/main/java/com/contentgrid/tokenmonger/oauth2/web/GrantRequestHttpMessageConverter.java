package com.contentgrid.tokenmonger.oauth2.web;

import com.contentgrid.tokenmonger.oauth2.OAuth2ErrorException;
import com.contentgrid.tokenmonger.oauth2.grants.GrantRequest;
import java.io.IOException;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.core.ResolvableType;
import org.springframework.core.convert.ConversionFailedException;
import org.springframework.core.convert.ConversionService;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.MultiValueMap;

@RequiredArgsConstructor
public class GrantRequestHttpMessageConverter implements HttpMessageConverter<GrantRequest> {

    private static final TypeDescriptor MULTI_VALUE_MAP_TYPE_DESCRIPTOR = new TypeDescriptor(
            ResolvableType.forClassWithGenerics(MultiValueMap.class, String.class, String.class), null, null);
    private static final TypeDescriptor GRANT_REQUEST_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(GrantRequest.class);

    private final FormHttpMessageConverter formHttpMessageConverter = new FormHttpMessageConverter();
    {
        formHttpMessageConverter.setSupportedMediaTypes(List.of(MediaType.APPLICATION_FORM_URLENCODED));
    }

    private final ConversionService conversionService;

    @Override
    public boolean canRead(Class<?> clazz, MediaType mediaType) {
        if(!GrantRequest.class.isAssignableFrom(clazz)) {
            return false;
        }
        return formHttpMessageConverter.canRead(MultiValueMap.class, mediaType);
    }

    @Override
    public boolean canWrite(Class<?> clazz, MediaType mediaType) {
        return false;
    }

    @Override
    public List<MediaType> getSupportedMediaTypes() {
        return formHttpMessageConverter.getSupportedMediaTypes();
    }

    @Override
    public GrantRequest read(Class<? extends GrantRequest> clazz, HttpInputMessage inputMessage)
            throws IOException, HttpMessageNotReadableException {
        var multiValueMap = formHttpMessageConverter.read(
                null,
                inputMessage
        );

        try {
            var conversionResult = conversionService.convert(multiValueMap, MULTI_VALUE_MAP_TYPE_DESCRIPTOR,
                    GRANT_REQUEST_TYPE_DESCRIPTOR);
            if(conversionResult == null) {
                throw new OAuth2ErrorException(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE);
            }
            if(!clazz.isInstance(conversionResult)) {
                throw new OAuth2ErrorException(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE);
            }
            return (GrantRequest) conversionResult;
        } catch(ConversionFailedException conversionFailedException) {
            if(conversionFailedException.getCause() instanceof OAuth2ErrorException oAuth2ErrorException) {
                throw new OAuth2ErrorException(oAuth2ErrorException.getError(), conversionFailedException);
            } else {
                throw new OAuth2ErrorException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), conversionFailedException);
            }
        }
    }

    @Override
    public void write(GrantRequest grantRequest, MediaType contentType, HttpOutputMessage outputMessage)
            throws IOException, HttpMessageNotWritableException {
        throw new UnsupportedOperationException();

    }
}
