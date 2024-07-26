package com.contentgrid.tokenmonger.validation;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.ElementType.CONSTRUCTOR;
import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE_USE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

@Constraint(validatedBy = IssuerOrJwkSetUriNotEmptyValidator.class)
@Target({ METHOD, FIELD, ANNOTATION_TYPE, CONSTRUCTOR, PARAMETER, TYPE_USE })
@Retention(RUNTIME)
public @interface IssuerOrJwkSetUriNotEmpty {
    String message() default "{com.contentgrid.tokenmonger.validation.IssuerOrJwkSetUriNotEmpty.message}";

    Class<?>[] groups() default { };

    Class<? extends Payload>[] payload() default { };
}
