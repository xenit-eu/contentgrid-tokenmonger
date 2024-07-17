package com.contentgrid.tokenmonger.jwk.source;

import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Predicate;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class RandomJWKSelectionJWKSource<C extends SecurityContext> implements JWKSource<C> {
    private static final Random RANDOM = new SecureRandom();
    private final JWKSource<C> delegate;

    @Override
    public List<JWK> get(JWKSelector jwkSelector, C context) throws KeySourceException {
        var keys = delegate.get(jwkSelector, context);
        var randomIndex = RANDOM.nextInt(keys.size());
        return keys.subList(randomIndex, 1);
    }
}
