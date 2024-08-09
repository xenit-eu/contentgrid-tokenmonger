package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.configuration.applications.ApplicationId;
import com.contentgrid.tokenmonger.apps.ContentgridApp;
import com.contentgrid.tokenmonger.oauth2.grants.GrantRequest;
import com.contentgrid.tokenmonger.web.validator.SingleApplicationResourceGrantRequestValidator.ApplicationInformation;
import java.util.Set;
import java.util.function.Function;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;

@RequiredArgsConstructor
public class TokenApplicationInformationGrantRequestValidator<C extends ApplicationInformation> implements GrantRequestValidator<GrantRequest, C> {
    private final Function<C, Jwt> tokenExtractor;

    @Override
    public void validate(GrantRequest grantRequest, C context) {
        var token = tokenExtractor.apply(context);

        context.setApplication(new ContentgridApp(
                ApplicationId.from(token.getClaimAsString("context:application:id")),
                Set.copyOf(token.getClaimAsStringList("context:application:domains"))
        ));

    }
}
