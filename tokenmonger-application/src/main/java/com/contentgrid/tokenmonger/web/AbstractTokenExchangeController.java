package com.contentgrid.tokenmonger.web;

import com.contentgrid.tokenmonger.oauth2.OAuth2ServerConfiguration;
import com.contentgrid.tokenmonger.oauth2.grants.GrantResponse;
import com.contentgrid.tokenmonger.oauth2.grants.GrantResponse.TokenType;
import com.contentgrid.tokenmonger.oauth2.grants.GrantType;
import com.contentgrid.tokenmonger.oauth2.grants.TokenExchangeGrantRequest;
import com.contentgrid.tokenmonger.web.validator.GrantRequestValidator;
import com.contentgrid.tokenmonger.oauth2.token.Token;
import com.contentgrid.tokenmonger.oauth2.token.TokenTypeIdentifier;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

@RequiredArgsConstructor
abstract class AbstractTokenExchangeController<C> {

    private final OAuth2ServerConfiguration oAuth2ServerConfiguration;

    private final List<GrantRequestValidator<TokenExchangeGrantRequest, C>> validators;

    @PostMapping(
            value = "token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public GrantResponse token(
            @RequestBody TokenExchangeGrantRequest tokenExchangeGrantRequest
    ) {
        var context = createContext();

        for (GrantRequestValidator<TokenExchangeGrantRequest, C> validator : validators) {
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


    @GetMapping(
            value = "jwks",
            produces = {
                    "application/jwk-set+json",
                    MediaType.APPLICATION_JSON_VALUE,
            }
    )
    public JWKSet jwkSet() {
        return oAuth2ServerConfiguration.getJwkSet().toPublicJWKSet();
    }

    @GetMapping(
            value = ".well-known/openid-configuration",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public OAuth2ServerMetadata oAuth2ServerMetadata() {
        return OAuth2ServerMetadata.builder()
                .issuer(oAuth2ServerConfiguration.getIssuer())
                .grantTypesSupported(List.of(GrantType.TOKEN_EXCHANGE))
                .build();
    }


}
