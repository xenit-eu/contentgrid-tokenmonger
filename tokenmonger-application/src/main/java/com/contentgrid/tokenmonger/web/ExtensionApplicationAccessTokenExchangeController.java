package com.contentgrid.tokenmonger.web;

import com.contentgrid.tokenmonger.IssuerContext;
import com.contentgrid.tokenmonger.IssuerContext.IssuerType;
import com.contentgrid.tokenmonger.TokenExpiryPolicy;
import com.contentgrid.tokenmonger.application.Application;
import com.contentgrid.tokenmonger.application.ApplicationRepository;
import com.contentgrid.tokenmonger.oauth2.OAuth2ServerConfiguration;
import com.contentgrid.tokenmonger.oauth2.grants.TokenExchangeGrantRequest;
import com.contentgrid.tokenmonger.oauth2.token.decoder.TokenDecoder;
import com.contentgrid.tokenmonger.web.ExtensionApplicationAccessTokenExchangeController.Context;
import com.contentgrid.tokenmonger.web.validator.ApplicationResourceAllowedGrantRequestValidator;
import com.contentgrid.tokenmonger.web.validator.ApplicationResourceAllowedGrantRequestValidator.ApplicationResourceInformation;
import com.contentgrid.tokenmonger.web.validator.NoActorTokenExchangeGrantRequestValidator;
import com.contentgrid.tokenmonger.web.validator.NoAudienceGrantRequestValidator;
import com.contentgrid.tokenmonger.web.validator.NoScopeGrantRequestValidator;
import com.contentgrid.tokenmonger.web.validator.SingleApplicationResourceGrantRequestValidator;
import com.contentgrid.tokenmonger.web.validator.SingleApplicationResourceGrantRequestValidator.ApplicationInformation;
import com.contentgrid.tokenmonger.web.validator.SubjectTokenGrantRequestValidator;
import com.contentgrid.tokenmonger.web.validator.SubjectTokenGrantRequestValidator.SubjectTokenInfo;
import java.util.List;
import lombok.Data;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.web.bind.annotation.RestController;

@RestController
@IssuerContext(IssuerType.EXTENSION_APPLICATION_ACCESS_TOKEN)
public class ExtensionApplicationAccessTokenExchangeController extends AbstractTokenGrantController<TokenExchangeGrantRequest, Context> {

    private final TokenExpiryPolicy tokenExpiryPolicy;

    public ExtensionApplicationAccessTokenExchangeController(
            @IssuerContext(IssuerType.EXTENSION_APPLICATION_ACCESS_TOKEN)
            OAuth2ServerConfiguration eaatServerConfiguration,
            @IssuerContext(IssuerType.EXTENSION_IDENTITY_TOKEN)
            TokenDecoder<Jwt> eitDecoder,
            ApplicationRepository applicationRepository,
            TokenExpiryPolicy tokenExpiryPolicy
    ) {
        super(
                eaatServerConfiguration,
                List.of(
                        new NoActorTokenExchangeGrantRequestValidator<>(),
                        new NoAudienceGrantRequestValidator<>(),
                        new NoScopeGrantRequestValidator<>(),
                        new SingleApplicationResourceGrantRequestValidator<>(applicationRepository),
                        new ApplicationResourceAllowedGrantRequestValidator<>(),
                        new SubjectTokenGrantRequestValidator<>(eitDecoder)
                ));
        this.tokenExpiryPolicy = tokenExpiryPolicy;
    }

    @Override
    protected String getDescription() {
        return "Tokens to authenticate an extension to an application";
    }

    @Override
    protected Context createContext() {
        return new Context();
    }

    @Override
    protected JwtClaimsSet createToken(Context context) {
        return JwtClaimsSet.builder()
                .subject(context.getSubjectToken().getSubject())
                .audience(List.of("contentgrid:application:"+context.getApplication().getApplicationId()))
                .claim("context:application:resource", context.getApplicationResourcePaths())
                .expiresAt(tokenExpiryPolicy.getExpiry(context.getSubjectToken().getExpiresAt()))
                .build();
    }

    @Data
    protected static class Context implements ApplicationInformation, ApplicationResourceInformation, SubjectTokenInfo {
        private Application application;
        private List<String> applicationResourcePaths;
        private Jwt subjectToken;
    }

}
