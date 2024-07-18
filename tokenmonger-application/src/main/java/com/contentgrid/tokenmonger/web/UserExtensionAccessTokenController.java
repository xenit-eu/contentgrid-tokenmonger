package com.contentgrid.tokenmonger.web;

import com.contentgrid.tokenmonger.IssuerContext;
import com.contentgrid.tokenmonger.IssuerContext.IssuerType;
import com.contentgrid.tokenmonger.TokenExpiryPolicy;
import com.contentgrid.tokenmonger.TokenmongerProperties;
import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtensionRepository;
import com.contentgrid.tokenmonger.oauth2.OAuth2ErrorException;
import com.contentgrid.tokenmonger.oauth2.OAuth2ServerConfiguration;
import com.contentgrid.tokenmonger.oauth2.grants.ContentgridExtensionTokenGrantRequest;
import com.contentgrid.tokenmonger.oauth2.grants.GrantResponse;
import com.contentgrid.tokenmonger.oauth2.grants.GrantResponse.TokenType;
import com.contentgrid.tokenmonger.oauth2.grants.GrantType;
import com.contentgrid.tokenmonger.oauth2.token.Token;
import com.contentgrid.tokenmonger.oauth2.token.TokenTypeIdentifier;
import com.contentgrid.tokenmonger.web.annotation.JwkSetEndpointMapping;
import com.contentgrid.tokenmonger.web.annotation.OAuthServerConfigurationEndpointMapping;
import com.contentgrid.tokenmonger.web.annotation.TokenEndpointMapping;
import com.contentgrid.tokenmonger.web.validator.NoScopeGrantRequestValidator;
import com.nimbusds.jose.jwk.JWKSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({
        ".contentgrid/authentication/external",
        "authentication/external"
})
public class UserExtensionAccessTokenController {
    private final OAuth2ServerConfiguration oAuth2ServerConfiguration;
    private final RegisteredExtensionRepository registeredExtensionRepository;
    private final TokenExpiryPolicy tokenExpiryPolicy;
    private final TokenmongerProperties tokenmongerProperties;

    public UserExtensionAccessTokenController(
            @IssuerContext(IssuerType.USER_EXTENSION_ACCESS_TOKEN)
            OAuth2ServerConfiguration oAuth2ServerConfiguration,
            RegisteredExtensionRepository registeredExtensionRepository,
            TokenExpiryPolicy tokenExpiryPolicy,
            TokenmongerProperties tokenmongerProperties
    ) {
        this.oAuth2ServerConfiguration = oAuth2ServerConfiguration;
        this.registeredExtensionRepository = registeredExtensionRepository;
        this.tokenExpiryPolicy = tokenExpiryPolicy;
        this.tokenmongerProperties = tokenmongerProperties;
    }

    @TokenEndpointMapping
    public GrantResponse token(
            @AuthenticationPrincipal Jwt userToken,
            @RequestBody ContentgridExtensionTokenGrantRequest grantRequest
    ) {

        if(userToken == null) {
            throw new OAuth2ErrorException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, "Bearer authentication is required", "about:blank"));
        }

        new NoScopeGrantRequestValidator<>().validate(grantRequest, null);

        var extension = registeredExtensionRepository.findByResourceUri(grantRequest.getResource().toString())
                .orElseThrow(() -> new OAuth2ErrorException(new OAuth2Error("invalid_target", "No extension is registered for the requested resource", "about:blank")));

        var claimBuilder = JwtClaimsSet.builder()
                .subject(userToken.getIssuer().toString()+"#"+userToken.getSubject())
                .audience(List.of("contentgrid:extension:"+extension.getExtensionId()))
                .expiresAt(tokenExpiryPolicy.getExpiry(userToken.getExpiresAt()))
                .claim("may_act", Map.of(
                        JwtClaimNames.ISS, tokenmongerProperties.getExtensionIdentity().getIssuer(),
                        JwtClaimNames.SUB, extension.getExtensionId()
                ));

        userToken.getClaims()
                .forEach((claimName, claimValue) -> {
                    if (shouldCopy(claimName)) {
                        claimBuilder.claim(claimName, claimValue);
                    }
                });

        var issuedToken = oAuth2ServerConfiguration.getJwtEncoder()
                .encode(JwtEncoderParameters.from(claimBuilder.build()));

        return GrantResponse.builder()
                .accessToken(new Token(issuedToken.getTokenValue(), TokenTypeIdentifier.ACCESS_TOKEN))
                .tokenType(TokenType.BEARER)
                .expiresAt(issuedToken.getExpiresAt())
                .build();
    }

    private static boolean shouldCopy(String claimName) {
        if(Objects.equals("act", claimName)) {
            return true;
        }
        return claimName.startsWith("restrict:") || claimName.startsWith("context:");
    }

    @OAuthServerConfigurationEndpointMapping
    public OAuth2ServerMetadata oAuth2ServerMetadata() {
        return OAuth2ServerMetadata.builder()
                .issuer(oAuth2ServerConfiguration.getIssuer())
                .grantTypesSupported(List.of(GrantType.CONTENTGRID_EXTENSION))
                .build();
    }

    @JwkSetEndpointMapping
    public JWKSet jwkSet() {
        return oAuth2ServerConfiguration.getJwkSet().toPublicJWKSet();
    }
}
