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
@IssuerContextCombinationMapping(Operation.PREPEND)
@RequestMapping(
        method = RequestMethod.POST,
        path = "token",
        consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
)
public @interface TokenEndpointMapping {

}
