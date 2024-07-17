package com.contentgrid.tokenmonger;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.beans.factory.annotation.Qualifier;

@Qualifier
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER, ElementType.TYPE, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface IssuerContext {
    IssuerType value();

    public enum IssuerType {
        USER_APPLICATION_ACCESS_TOKEN,
        EXTENSION_IDENTITY_TOKEN,
        USER_EXTENSION_ACCESS_TOKEN,
        EXTENSION_APPLICATION_ACCESS_TOKEN,
        EXTENSION_DELEGATED_APPLICATION_ACCESS_TOKEN,
    }

}
