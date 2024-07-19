package com.contentgrid.tokenmonger.web.mapping;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.web.bind.annotation.Mapping;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Mapping
public @interface IssuerContextCombinationMapping {
    Operation value();

    enum Operation {
        IGNORE,
        PREPEND,
        APPEND
    }
}
