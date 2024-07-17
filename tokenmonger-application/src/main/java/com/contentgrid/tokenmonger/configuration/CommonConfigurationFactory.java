package com.contentgrid.tokenmonger.configuration;

import com.contentgrid.tokenmonger.TokenmongerProperties.TokenDecoderProperties;
import com.contentgrid.tokenmonger.TokenmongerProperties.TokenEncoderProperties;
import com.contentgrid.tokenmonger.jwk.source.FilebasedJWKSetSource;
import com.contentgrid.tokenmonger.jwk.source.JWKSourceWrapperBuilder;
import com.contentgrid.tokenmonger.jwk.source.LoggingJWKSetSourceEventListener;
import com.contentgrid.tokenmonger.oauth2.OAuth2ServerConfiguration;
import com.contentgrid.tokenmonger.oauth2.jwt.JwtDecoderBuilder;
import com.contentgrid.tokenmonger.oauth2.token.decoder.JwtTokenDecoder;
import com.contentgrid.tokenmonger.oauth2.token.decoder.TokenDecoder;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.security.oauth2.jwt.Jwt;

@RequiredArgsConstructor
public class CommonConfigurationFactory {
    private final ResourcePatternResolver resourcePatternResolver;

    public JWKSource<SecurityContext> jwkSource(TokenEncoderProperties tokenEncoderProperties) {
        if(tokenEncoderProperties.getActiveSigningKeys() == null) {
            return null;
        }

        var fileJwkSource = new FilebasedJWKSetSource(
                resourcePatternResolver,
                tokenEncoderProperties.getActiveSigningKeys(),
                tokenEncoderProperties.getRetiredSigningKeys()
        );

        var cachedJwkSource = JWKSourceBuilder.create(fileJwkSource)
                .refreshAheadCache(JWKSourceBuilder.DEFAULT_REFRESH_AHEAD_TIME, true, new LoggingJWKSetSourceEventListener<>())
                .build();
        return JWKSourceWrapperBuilder.from(cachedJwkSource)
                .filterByAlgorithms(tokenEncoderProperties.getJwsAlgorithms())
                .build();
    }

    public OAuth2ServerConfiguration oauth2ServerConfiguration(
            TokenEncoderProperties tokenEncoderProperties,
            JWKSource<SecurityContext> jwkSource
    ) {
        return OAuth2ServerConfiguration.builder()
                .issuer(tokenEncoderProperties.getIssuer())
                .jwkSource(jwkSource)
                .jwsAlgorithms(tokenEncoderProperties.getJwsAlgorithms())
                .build();
    }

    public TokenDecoder<Jwt> tokenDecoder(
            TokenEncoderProperties tokenEncoderProperties,
            JWKSource<SecurityContext> jwkSource
    ) {
        return new JwtTokenDecoder(
                JwtDecoderBuilder.create()
                        .issuer(tokenEncoderProperties.getIssuer())
                        .jwkSource(jwkSource)
                        .jwsAlgorithms(tokenEncoderProperties.getJwsAlgorithms())
                        .build()
        );
    }

    public TokenDecoder<Jwt> tokenDecoder(
            TokenDecoderProperties tokenDecoderProperties
    ) {

        return new JwtTokenDecoder(
                JwtDecoderBuilder.create()
                        .issuer(tokenDecoderProperties.getIssuer())
                        .jwkSetUri(tokenDecoderProperties.getJwkSetUri())
                        .jwsAlgorithms(tokenDecoderProperties.getJwsAlgorithms())
                        .build()
        );
    }
}
