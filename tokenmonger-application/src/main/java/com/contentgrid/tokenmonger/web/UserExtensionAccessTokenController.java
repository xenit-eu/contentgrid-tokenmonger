package com.contentgrid.tokenmonger.web;

import com.contentgrid.tokenmonger.IssuerContext;
import com.contentgrid.tokenmonger.IssuerContext.IssuerType;
import com.contentgrid.tokenmonger.TokenExpiryPolicy;
import com.contentgrid.tokenmonger.TokenmongerProperties;
import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtension;
import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtensionRepository;
import com.contentgrid.tokenmonger.oauth2.OAuth2ServerConfiguration;
import com.contentgrid.tokenmonger.oauth2.error.OAuth2ErrorBuilder;
import com.contentgrid.tokenmonger.oauth2.grants.ContentgridExtensionTokenGrantRequest;
import com.contentgrid.tokenmonger.oauth2.grants.GrantResponse;
import com.contentgrid.tokenmonger.oauth2.grants.GrantType;
import com.contentgrid.tokenmonger.web.UserExtensionAccessTokenController.Context;
import com.contentgrid.tokenmonger.web.mapping.IssuerContextCombinationMapping;
import com.contentgrid.tokenmonger.web.mapping.IssuerContextCombinationMapping.Operation;
import com.contentgrid.tokenmonger.web.mapping.OAuthServerConfigurationEndpointMapping;
import com.contentgrid.tokenmonger.web.validator.NoScopeGrantRequestValidator;
import com.contentgrid.tokenmonger.web.validator.SingleExtensionResourceGrantRequestValidator;
import com.contentgrid.tokenmonger.web.validator.SingleExtensionResourceGrantRequestValidator.ExtensionInformation;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import lombok.Data;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@IssuerContext(IssuerType.USER_EXTENSION_ACCESS_TOKEN)
public class UserExtensionAccessTokenController extends AbstractTokenGrantController<ContentgridExtensionTokenGrantRequest, Context> {

    public static final String CONTENTGRID_AUTHENTICATION_EXTERNAL_TOKEN_PATH = "/.contentgrid/authentication/external/token";
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
    @IssuerContextCombinationMapping(Operation.IGNORE)
    @PostMapping(
            path = CONTENTGRID_AUTHENTICATION_EXTERNAL_TOKEN_PATH,
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public GrantResponse token(ContentgridExtensionTokenGrantRequest tokenExchangeGrantRequest) {
        return super.token(tokenExchangeGrantRequest);
    }

    @Override
    protected String getDescription() {
        return "Tokens to authenticate an end-user to an extension. The token endpoint is available at '<application root>/"+CONTENTGRID_AUTHENTICATION_EXTERNAL_TOKEN_PATH+"'";
    }

    @Override
    @OAuthServerConfigurationEndpointMapping
    public OAuth2ServerMetadata oAuth2ServerMetadata() {
        return super.oAuth2ServerMetadata().toBuilder()
                .tokenEndpoint(null)
                .grantTypesSupported(List.of(GrantType.CONTENTGRID_EXTENSION))
                .build();
    }

    @Override
    protected Context createContext() {
        return new Context();
    }

    @Override
    protected JwtClaimsSet createToken(Context context) {
        var principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if(!(principal instanceof Jwt)) {
            throw OAuth2ErrorBuilder.create(OAuth2ErrorCodes.ACCESS_DENIED)
                    .description("bearer authentication is required")
                    .buildException();
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
