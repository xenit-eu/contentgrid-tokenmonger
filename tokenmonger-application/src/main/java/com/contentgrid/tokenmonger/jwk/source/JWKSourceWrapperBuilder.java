package com.contentgrid.tokenmonger.jwk.source;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.util.Set;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import lombok.RequiredArgsConstructor;


@RequiredArgsConstructor(staticName = "from")
public class JWKSourceWrapperBuilder<C extends SecurityContext> {
    private final JWKSource<C> jwkSource;
    private Function<JWKSource<C>, JWKSource<C>> wrapper = UnaryOperator.identity();

    public JWKSourceWrapperBuilder<C> wrap(UnaryOperator<JWKSource<C>> wrapper) {
        this.wrapper = this.wrapper.andThen(wrapper);
        return this;
    }

    public JWKSourceWrapperBuilder<C> filterExpired() {
        return wrap(ExpiredJWKFilteringJWKSource::new);
    }

    public JWKSourceWrapperBuilder<C> selectOneRandom() {
        return wrap(RandomJWKSelectionJWKSource::new);
    }

    public JWKSourceWrapperBuilder<C> filterByAlgorithms(Set<JWSAlgorithm> jwsAlgorithms) {
        return wrap(source -> new AlgorithmBasedJWKFilteringJWKSource<>(source, jwsAlgorithms));
    }

    public JWKSource<C> build() {
        return wrapper.apply(jwkSource);
    }
}
