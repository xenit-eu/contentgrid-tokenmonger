package com.contentgrid.tokenmonger.web;

import com.contentgrid.tokenmonger.oauth2.OAuth2ServerConfiguration;
import com.contentgrid.tokenmonger.oauth2.grants.GrantResponse;
import com.contentgrid.tokenmonger.oauth2.grants.GrantResponse.TokenType;
import com.contentgrid.tokenmonger.oauth2.grants.GrantType;
import com.contentgrid.tokenmonger.oauth2.grants.TokenExchangeGrantRequest;
import com.contentgrid.tokenmonger.web.annotation.JwkSetEndpointMapping;
import com.contentgrid.tokenmonger.web.annotation.OAuthServerConfigurationEndpointMapping;
import com.contentgrid.tokenmonger.web.annotation.TokenEndpointMapping;
import com.contentgrid.tokenmonger.web.validator.GrantRequestValidator;
import com.contentgrid.tokenmonger.oauth2.token.Token;
import com.contentgrid.tokenmonger.oauth2.token.TokenTypeIdentifier;
import com.nimbusds.jose.jwk.JWKSet;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.RequestBody;

@RequiredArgsConstructor
abstract class AbstractTokenExchangeController<C> {

    protected final OAuth2ServerConfiguration oAuth2ServerConfiguration;
    private final List<GrantRequestValidator<? super TokenExchangeGrantRequest, C>> validators;


    @TokenEndpointMapping
    public GrantResponse token(
            @RequestBody TokenExchangeGrantRequest tokenExchangeGrantRequest
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

    protected abstract C createContext();

    protected abstract JwtClaimsSet createToken(C context);

    @OAuthServerConfigurationEndpointMapping
    public OAuth2ServerMetadata oAuth2ServerMetadata() {
        return OAuth2ServerMetadata.builder()
                .issuer(oAuth2ServerConfiguration.getIssuer())
                .grantTypesSupported(List.of(GrantType.TOKEN_EXCHANGE))
                .build();
    }

    @JwkSetEndpointMapping
    public JWKSet jwkSet() {
        return oAuth2ServerConfiguration.getJwkSet().toPublicJWKSet();
    }
}
