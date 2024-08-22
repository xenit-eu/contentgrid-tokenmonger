package com.contentgrid.tokenmonger.oauth2.token.decoder;

import com.contentgrid.tokenmonger.oauth2.error.OAuth2ErrorException;
import com.contentgrid.tokenmonger.oauth2.error.OAuth2ErrorBuilder;
import com.contentgrid.tokenmonger.oauth2.token.Token;
import com.contentgrid.tokenmonger.oauth2.token.TokenTypeIdentifier;
import com.nimbusds.jwt.JWTParser;
import java.text.ParseException;
import java.util.Objects;
import java.util.Set;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

@RequiredArgsConstructor
public class JwtTokenDecoder implements TokenDecoder<Jwt> {

    private static final Set<TokenTypeIdentifier> SUPPORTED_TYPES = Set.of(
            TokenTypeIdentifier.ACCESS_TOKEN,
            TokenTypeIdentifier.JWT
    );

    @Nullable
    private final String issuer;
    @NonNull
    private final JwtDecoder jwtDecoder;

    @Override
    public boolean supports(Token token) {
        return SUPPORTED_TYPES.contains(token.getType());
    }

    @Override
    public Jwt decode(Token token, OAuth2ErrorBuilder errorBuilder) {
        if(!supports(token)) {
            throw errorBuilder.description("unsupported token type").buildException();
        }

        try {
            var jwtIssuer = JWTParser.parse(token.getValue()).getJWTClaimsSet().getIssuer();
            if(issuer != null && !Objects.equals(jwtIssuer, issuer)) {
                throw errorBuilder.description("must be issued by '%s'".formatted(issuer)).buildException();
            }
        } catch (ParseException e) {
            throw new OAuth2ErrorException(errorBuilder.description("is malformed").build(), e);
        }
        try {
            return jwtDecoder.decode(token.getValue());
        } catch(JwtException ex) {
            throw new OAuth2ErrorException(errorBuilder.description("can not be decoded").build(), ex);
        }
    }
}
