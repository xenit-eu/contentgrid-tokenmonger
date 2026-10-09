package com.contentgrid.tokenmonger.web;

import com.contentgrid.tokenmonger.oauth2.OAuth2ServerConfiguration;
import com.contentgrid.tokenmonger.oauth2.grants.GrantRequest;
import com.contentgrid.tokenmonger.oauth2.grants.GrantResponse;
import com.contentgrid.tokenmonger.oauth2.grants.GrantResponse.TokenType;
import com.contentgrid.tokenmonger.oauth2.grants.GrantType;
import com.contentgrid.tokenmonger.oauth2.token.Token;
import com.contentgrid.tokenmonger.oauth2.token.TokenTypeIdentifier;
import com.contentgrid.tokenmonger.web.mapping.IssuerContextCombinationMapping;
import com.contentgrid.tokenmonger.web.mapping.IssuerContextCombinationMapping.Operation;
import com.contentgrid.tokenmonger.web.mapping.JwkSetEndpointMapping;
import com.contentgrid.tokenmonger.web.mapping.OAuthServerConfigurationEndpointMapping;
import com.contentgrid.tokenmonger.web.mapping.TokenEndpointMapping;
import com.contentgrid.tokenmonger.web.validator.GrantRequestValidator;
import com.nimbusds.jose.jwk.JWKSet;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.servlet.ModelAndView;


@RequiredArgsConstructor
abstract class AbstractTokenGrantController<T extends GrantRequest, C> {

    protected final OAuth2ServerConfiguration oAuth2ServerConfiguration;
    private final List<GrantRequestValidator<? super T, C>> validators;

    @TokenEndpointMapping
    public GrantResponse token(
            @RequestBody T tokenExchangeGrantRequest
    ) {
        var context = createContext();

        for (var validator : validators) {
            validator.validate(tokenExchangeGrantRequest, context);
        }

        var tokenClaims = createToken(context);

        var issuedToken = oAuth2ServerConfiguration.getJwtEncoder().encode(JwtEncoderParameters.from(tokenClaims));

        return GrantResponse.builder()
                .accessToken(new Token(issuedToken.getTokenValue(), TokenTypeIdentifier.ACCESS_TOKEN))
                .tokenType(TokenType.BEARER)
                .expiresAt(issuedToken.getExpiresAt())
                .build();
    }

    protected abstract String getDescription();

    protected abstract C createContext();

    protected abstract JwtClaimsSet createToken(C context);

    @OAuthServerConfigurationEndpointMapping
    public OAuth2ServerMetadata oAuth2ServerMetadata() {
        return OAuth2ServerMetadata.builder()
                .issuer(oAuth2ServerConfiguration.getIssuer())
                .tokenEndpoint(oAuth2ServerConfiguration.getIssuer()+"/token")
                .jwksUri(oAuth2ServerConfiguration.getIssuer()+"/jwks")
                .grantTypesSupported(List.of(GrantType.TOKEN_EXCHANGE))
                .build();
    }


    @JwkSetEndpointMapping
    public JWKSet jwkSet() {
        return oAuth2ServerConfiguration.getJwkSet().toPublicJWKSet();
    }

    @GetMapping(
            path = "",
            produces = MediaType.TEXT_HTML_VALUE
    )
    @IssuerContextCombinationMapping(Operation.PREPEND)
    public ModelAndView issuerInformation() {
        return new ModelAndView("issuer-root", Map.of(
                "description", getDescription(),
                "serverMetadata", oAuth2ServerMetadata(),
                "serverConfiguration", oAuth2ServerConfiguration,
                "validators", validators
        ));
    }
}
