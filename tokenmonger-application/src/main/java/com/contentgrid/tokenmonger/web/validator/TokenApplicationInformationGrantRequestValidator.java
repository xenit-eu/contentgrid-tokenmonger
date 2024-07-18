package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.application.Application;
import com.contentgrid.tokenmonger.oauth2.grants.GrantRequest;
import com.contentgrid.tokenmonger.web.validator.SingleApplicationResourceGrantRequestValidator.ApplicationInformation;
import java.util.function.Function;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;

@RequiredArgsConstructor
public class TokenApplicationInformationGrantRequestValidator<C extends ApplicationInformation> implements GrantRequestValidator<GrantRequest, C> {
    private final Function<C, Jwt> tokenExtractor;

    @Override
    public void validate(GrantRequest grantRequest, C context) {
        var token = tokenExtractor.apply(context);

        context.setApplication(new Application(
                token.getClaimAsString("context:application:id"),
                token.getClaimAsStringList("context:application:domains")
        ));

    }
}
