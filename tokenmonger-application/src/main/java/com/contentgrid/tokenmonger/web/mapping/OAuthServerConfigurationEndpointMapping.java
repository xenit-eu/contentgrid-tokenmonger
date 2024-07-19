package com.contentgrid.tokenmonger.web.mapping;

import com.contentgrid.tokenmonger.web.mapping.IssuerContextCombinationMapping.Operation;
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
        path = {
                ".well-known/oauth-authorization-server",
                ".well-known/openid-configuration"
        },
        produces =  MediaType.APPLICATION_JSON_VALUE
)
@IssuerContextCombinationMapping(Operation.APPEND)
public @interface OAuthServerConfigurationEndpointMapping {

}
