package com.contentgrid.tokenmonger.jwk.source;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class AlgorithmBasedJWKFilteringJWKSource<C extends SecurityContext> implements JWKSource<C> {
    private final JWKSource<C> delegate;

    private final JWKMatcher additionalMatcher;

    public AlgorithmBasedJWKFilteringJWKSource(JWKSource<C> delegate, Set<JWSAlgorithm> acceptableAlgorithms) {
        this(delegate, createJWKMatcher(acceptableAlgorithms));

    }

    private static JWKMatcher createJWKMatcher(Set<JWSAlgorithm> acceptableAlgorithms) {
        return new JWKMatcher.Builder()
                .keyTypes(acceptableAlgorithms.stream().map(KeyType::forAlgorithm).collect(Collectors.toUnmodifiableSet()))
                .build();
    }

    @Override
    public List<JWK> get(JWKSelector jwkSelector, C context) throws KeySourceException {
        return delegate.get(jwkSelector, context)
                .stream()
                .filter(additionalMatcher::matches)
                .toList();
    }
}
