package com.contentgrid.tokenmonger.web.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@RequestMapping(
        method = RequestMethod.GET,
        value = "jwks",
        produces = {
                "application/jwk-set+json",
                MediaType.APPLICATION_JSON_VALUE,
        }
)
public @interface JwkSetEndpointMapping {

}
