package com.contentgrid.tokenmonger.test.mockmvc;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import lombok.SneakyThrows;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.mock.http.MockHttpOutputMessage;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.util.MultiValueMapAdapter;

public class EncodeToWwwFormRequestPostProcessor implements RequestPostProcessor {
    private static final FormHttpMessageConverter messageConverter = new FormHttpMessageConverter();

    @SneakyThrows(IOException.class)
    @Override
    public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
        var parameterMap = request.getParameterMap()
                .entrySet()
                .stream()
                .map(entry -> Map.entry(entry.getKey(), Arrays.asList(entry.getValue())))
                .collect(Collectors.toMap(Entry::getKey, Entry::getValue));

        var outputMessage = new MockHttpOutputMessage();

        messageConverter.write(new MultiValueMapAdapter<String, String>(parameterMap),
                MediaType.APPLICATION_FORM_URLENCODED, outputMessage);

        request.setContentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        request.setContent(outputMessage.getBodyAsBytes());

        return request;
    }
}
