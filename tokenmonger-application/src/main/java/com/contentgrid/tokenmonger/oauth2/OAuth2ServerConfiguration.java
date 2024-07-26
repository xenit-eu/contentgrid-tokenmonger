package com.contentgrid.tokenmonger.oauth2;

import com.contentgrid.tokenmonger.jwk.source.JWKSourceWrapperBuilder;
import com.contentgrid.tokenmonger.oauth2.jwt.IssuerInjectingJwtEncoder;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import java.net.URI;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.Value;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@Value
@Builder
public class OAuth2ServerConfiguration {
    private static final JWKSelector ALL_SELECTOR = new JWKSelector(new JWKMatcher.Builder().build());

    String issuer;

    Set<JWSAlgorithm> jwsAlgorithms;

    @Getter(value = AccessLevel.NONE)
    JWKSource<SecurityContext> jwkSource;

    InitializeOnce<JwtEncoder> jwtEncoder = new InitializeOnce<>(this::createJwtEncoder);

    public URI getOAuthServerMetadataUri() {
        var issuerUri = URI.create(issuer);

        return issuerUri.resolve("/.well-known/oauth-authorization-server"+issuerUri.getPath());
    }

    @SneakyThrows(KeySourceException.class)
    public JWKSet getJwkSet() {
        return new JWKSet(jwkSource.get(ALL_SELECTOR, new SimpleSecurityContext()));
    }

    private JwtEncoder createJwtEncoder() {
        return new IssuerInjectingJwtEncoder(
                issuer,
                new NimbusJwtEncoder(JWKSourceWrapperBuilder.from(jwkSource)
                        .filterExpired()
                        .selectOneRandom()
                        .build())
        );
    }

    public JwtEncoder getJwtEncoder() {
        return jwtEncoder.get();
    }

    @RequiredArgsConstructor
    private static class InitializeOnce<T> implements Supplier<T> {
        private final Supplier<T> creator;
        private final AtomicReference<T> instance = new AtomicReference<>();

        @Override
        public T get() {
            return instance.updateAndGet(instance -> Objects.requireNonNullElseGet(instance, creator));
        }

    }
}
