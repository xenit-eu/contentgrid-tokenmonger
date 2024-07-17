package com.contentgrid.tokenmonger.oauth2.token.decoder;

import com.contentgrid.tokenmonger.oauth2.OAuth2ErrorException;
import com.contentgrid.tokenmonger.oauth2.token.Token;
import com.contentgrid.tokenmonger.oauth2.token.TokenTypeIdentifier;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

@RequiredArgsConstructor
public class JwtTokenDecoder implements TokenDecoder<Jwt> {

    private static final Set<TokenTypeIdentifier> SUPPORTED_TYPES = Set.of(
            TokenTypeIdentifier.ACCESS_TOKEN,
            TokenTypeIdentifier.JWT
    );

    private final JwtDecoder jwtDecoder;

    @Override
    public boolean supports(Token token) {
        return SUPPORTED_TYPES.contains(token.getType());
    }

    @Override
    public Jwt decode(Token token) {
        if(!supports(token)) {
            throw new OAuth2ErrorException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), "Unsupported token type");
        }
        try {
            return jwtDecoder.decode(token.getValue());
        } catch(JwtException ex) {
            throw new OAuth2ErrorException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), ex);
        }
    }
}
