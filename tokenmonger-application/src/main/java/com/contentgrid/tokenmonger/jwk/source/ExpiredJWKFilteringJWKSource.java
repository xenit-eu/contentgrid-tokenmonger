package com.contentgrid.tokenmonger.jwk.source;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.util.Date;
import java.util.List;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class ExpiredJWKFilteringJWKSource<C extends SecurityContext> implements JWKSource<C> {
    private final JWKSource<C> delegate;

    @Override
    public List<JWK> get(JWKSelector jwkSelector, C context) throws KeySourceException {
        var now = new Date();
        return delegate.get(jwkSelector, context).stream()
                .filter(jwk -> isActive(jwk, now))
                .toList();
    }

    private static boolean isActive(JWK jwk, Date referenceTime) {
        if(jwk.getExpirationTime() == null) {
            return true;
        }
        return jwk.getExpirationTime().after(referenceTime);
    }
}
