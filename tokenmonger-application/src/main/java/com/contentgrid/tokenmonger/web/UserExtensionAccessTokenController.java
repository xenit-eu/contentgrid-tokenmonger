package com.contentgrid.tokenmonger.web;

import com.contentgrid.tokenmonger.IssuerContext;
import com.contentgrid.tokenmonger.IssuerContext.IssuerType;
import com.contentgrid.tokenmonger.TokenExpiryPolicy;
import com.contentgrid.tokenmonger.TokenmongerProperties;
import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtension;
import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtensionRepository;
import com.contentgrid.tokenmonger.oauth2.OAuth2ErrorException;
import com.contentgrid.tokenmonger.oauth2.OAuth2ServerConfiguration;
import com.contentgrid.tokenmonger.oauth2.grants.ContentgridExtensionTokenGrantRequest;
import com.contentgrid.tokenmonger.web.UserExtensionAccessTokenController.Context;
import com.contentgrid.tokenmonger.web.validator.NoScopeGrantRequestValidator;
import com.contentgrid.tokenmonger.web.validator.SingleExtensionResourceGrantRequestValidator;
import com.contentgrid.tokenmonger.web.validator.SingleExtensionResourceGrantRequestValidator.ExtensionInformation;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import lombok.Data;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({
        ".contentgrid/authentication/external",
        "authentication/external"
})
public class UserExtensionAccessTokenController extends AbstractTokenGrantController<ContentgridExtensionTokenGrantRequest, Context> {
    private final TokenExpiryPolicy tokenExpiryPolicy;
    private final TokenmongerProperties tokenmongerProperties;

    public UserExtensionAccessTokenController(
            @IssuerContext(IssuerType.USER_EXTENSION_ACCESS_TOKEN)
            OAuth2ServerConfiguration oAuth2ServerConfiguration,
            RegisteredExtensionRepository registeredExtensionRepository,
            TokenExpiryPolicy tokenExpiryPolicy,
            TokenmongerProperties tokenmongerProperties
    ) {
        super(
                oAuth2ServerConfiguration,
                List.of(
                        new NoScopeGrantRequestValidator<>(),
                        new SingleExtensionResourceGrantRequestValidator<>(registeredExtensionRepository)
                )
        );
        this.tokenExpiryPolicy = tokenExpiryPolicy;
        this.tokenmongerProperties = tokenmongerProperties;
    }


    @Override
    protected Context createContext() {
        return new Context();
    }

    @Override
    protected JwtClaimsSet createToken(Context context) {
        var principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if(!(principal instanceof Jwt)) {
            throw new OAuth2ErrorException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, "Bearer authentication is required", "about:blank"));
        }

        var userToken = (Jwt)principal;

        var claimBuilder = JwtClaimsSet.builder()
                .subject(userToken.getIssuer().toString()+"#"+userToken.getSubject())
                .audience(List.of("contentgrid:extension:"+context.getExtension().getExtensionId()))
                .expiresAt(tokenExpiryPolicy.getExpiry(userToken.getExpiresAt()))
                .claim("may_act", Map.of(
                        JwtClaimNames.ISS, tokenmongerProperties.getExtensionIdentity().getIssuer(),
                        JwtClaimNames.SUB, context.getExtension().getExtensionId()
                ));

        userToken.getClaims()
                .forEach((claimName, claimValue) -> {
                    if (shouldCopy(claimName)) {
                        claimBuilder.claim(claimName, claimValue);
                    }
                });

        return claimBuilder.build();
    }

    private static boolean shouldCopy(String claimName) {
        if(Objects.equals("act", claimName)) {
            return true;
        }
        return claimName.startsWith("restrict:") || claimName.startsWith("context:");
    }

    @Data
    public static class Context implements ExtensionInformation {
        private RegisteredExtension extension;
    }
}
