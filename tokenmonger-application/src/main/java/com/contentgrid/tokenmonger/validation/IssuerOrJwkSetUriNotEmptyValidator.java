package com.contentgrid.tokenmonger.validation;

import com.contentgrid.tokenmonger.TokenmongerProperties;
import com.contentgrid.tokenmonger.TokenmongerProperties.TokenDecoderProperties;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.util.StringUtils;

public class IssuerOrJwkSetUriNotEmptyValidator implements ConstraintValidator<IssuerOrJwkSetUriNotEmpty, TokenmongerProperties.TokenDecoderProperties> {

    @Override
    public boolean isValid(TokenDecoderProperties value, ConstraintValidatorContext context) {
        return StringUtils.hasText(value.getIssuer()) || StringUtils.hasText(value.getJwkSetUri());
    }

}
