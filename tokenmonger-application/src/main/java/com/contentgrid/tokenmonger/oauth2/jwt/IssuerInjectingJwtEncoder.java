package com.contentgrid.tokenmonger.oauth2.jwt;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtEncodingException;

@RequiredArgsConstructor
public class IssuerInjectingJwtEncoder implements JwtEncoder {

    @NonNull
    private final String issuer;

    @NonNull
    private final JwtEncoder delegate;

    @Override
    public Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException {
        var newClaimsSet = JwtClaimsSet.from(parameters.getClaims())
                .issuer(issuer)
                .build();

        var newParameters = parameters.getJwsHeader() == null?
                JwtEncoderParameters.from(newClaimsSet):
                JwtEncoderParameters.from(parameters.getJwsHeader(), newClaimsSet);

        return delegate.encode(newParameters);
    }
}
