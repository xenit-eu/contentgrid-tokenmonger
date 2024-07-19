package com.contentgrid.tokenmonger.web;

import com.contentgrid.tokenmonger.IssuerContext;
import com.contentgrid.tokenmonger.IssuerContext.IssuerType;
import com.contentgrid.tokenmonger.TokenExpiryPolicy;
import com.contentgrid.tokenmonger.application.Application;
import com.contentgrid.tokenmonger.oauth2.OAuth2ServerConfiguration;
import com.contentgrid.tokenmonger.oauth2.grants.TokenExchangeGrantRequest;
import com.contentgrid.tokenmonger.oauth2.token.decoder.TokenDecoder;
import com.contentgrid.tokenmonger.web.ExtensionDelegatedApplicationAccessTokenExchangeController.Context;
import com.contentgrid.tokenmonger.web.validator.ActorTokenGrantRequestValidator;
import com.contentgrid.tokenmonger.web.validator.ActorTokenGrantRequestValidator.ActorTokenInfo;
import com.contentgrid.tokenmonger.web.validator.NoAudienceGrantRequestValidator;
import com.contentgrid.tokenmonger.web.validator.NoScopeGrantRequestValidator;
import com.contentgrid.tokenmonger.web.validator.ApplicationResourceAllowedGrantRequestValidator;
import com.contentgrid.tokenmonger.web.validator.ApplicationResourceAllowedGrantRequestValidator.ApplicationResourceInformation;
import com.contentgrid.tokenmonger.web.validator.SingleApplicationResourceGrantRequestValidator.ApplicationInformation;
import com.contentgrid.tokenmonger.web.validator.SubjectTokenGrantRequestValidator;
import com.contentgrid.tokenmonger.web.validator.SubjectTokenGrantRequestValidator.SubjectTokenInfo;
import com.contentgrid.tokenmonger.web.validator.TokenApplicationInformationGrantRequestValidator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.Data;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@IssuerContext(IssuerType.EXTENSION_DELEGATED_APPLICATION_ACCESS_TOKEN)
public class ExtensionDelegatedApplicationAccessTokenExchangeController extends AbstractTokenGrantController<TokenExchangeGrantRequest, Context> {

    private final TokenExpiryPolicy tokenExpiryPolicy;

    public ExtensionDelegatedApplicationAccessTokenExchangeController(
            @IssuerContext(IssuerType.EXTENSION_DELEGATED_APPLICATION_ACCESS_TOKEN)
            OAuth2ServerConfiguration edaatServerConfiguration,
            @IssuerContext(IssuerType.USER_EXTENSION_ACCESS_TOKEN)
            TokenDecoder<Jwt> ueatDecoder,
            @IssuerContext(IssuerType.EXTENSION_IDENTITY_TOKEN)
            TokenDecoder<Jwt> eitDecoder,
            TokenExpiryPolicy tokenExpiryPolicy
    ) {
        super(
                edaatServerConfiguration,
                List.of(
                        new NoAudienceGrantRequestValidator<>(),
                        new NoScopeGrantRequestValidator<>(),
                        new SubjectTokenGrantRequestValidator<>(ueatDecoder),
                        new ActorTokenGrantRequestValidator<>(eitDecoder),
                        new TokenApplicationInformationGrantRequestValidator<>(Context::getSubjectToken),
                        new ApplicationResourceAllowedGrantRequestValidator<>()
                ));
        this.tokenExpiryPolicy = tokenExpiryPolicy;
    }

    @Override
    protected Context createContext() {
        return new Context();
    }

    @Override
    protected JwtClaimsSet createToken(Context context) {
        var builder = JwtClaimsSet.builder()
                .subject(context.getSubjectToken().getSubject())
                .audience(List.of("contentgrid:application:"+context.getApplication().getApplicationId()))
                .claim("context:application:resource", context.getApplicationResourcePaths())
                .expiresAt(tokenExpiryPolicy.getExpiry(context.getSubjectToken().getExpiresAt()))
                .claim("act", assembleActors(context.getActorToken(), context.getSubjectToken().getClaimAsMap("act")));

        context.getSubjectToken().getClaims().forEach((claimName, claimValue) -> {
            if(claimName.startsWith("restrict:")) {
                builder.claim(claimName, claimValue);
            }
        });

       return builder.build();
    }

    private static Map<String, Object> assembleActors(Jwt actorToken, Map<String, Object> parentActors) {
        var actor = new LinkedHashMap<String, Object>();
        actor.put(JwtClaimNames.ISS, actorToken.getIssuer());
        actor.put(JwtClaimNames.SUB, actorToken.getSubject());
        if(parentActors != null) {
            actor.put("act", parentActors);
        }
        return actor;
    }

    @Data
    protected static class Context implements ApplicationInformation, ApplicationResourceInformation, SubjectTokenInfo, ActorTokenInfo {
        private Application application;
        private List<String> applicationResourcePaths;
        private Jwt subjectToken;
        private Jwt actorToken;
    }

}
