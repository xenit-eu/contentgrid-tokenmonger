package com.contentgrid.tokenmonger.oauth2.web;

import com.contentgrid.tokenmonger.oauth2.grants.GrantRequest;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@RequiredArgsConstructor
@Component
public class OAuth2WebMvcConfigurer implements WebMvcConfigurer {
    private final List<Converter<MultiValueMap<String, String>, ? extends GrantRequest>> converters;

    @Override
    public void configureMessageConverters(List<HttpMessageConverter<?>> httpMessageConverters) {
        var conversionService = new GenericConversionService();
        converters.forEach(conversionService::addConverter);
        httpMessageConverters.add(0, new GrantRequestHttpMessageConverter(conversionService));
        httpMessageConverters.add(0, new GrantResponseHttpMessageConverter());
    }
}
