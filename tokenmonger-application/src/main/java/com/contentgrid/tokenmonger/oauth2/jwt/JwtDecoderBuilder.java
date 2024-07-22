package com.contentgrid.tokenmonger.oauth2.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder;

@Accessors(fluent = true)
@Setter
@NoArgsConstructor(staticName = "create")
public class JwtDecoderBuilder {

    private String issuer;
    private String jwkSetUri;
    private JWKSource<SecurityContext> jwkSource;
    private List<String> audience;
    private Set<JWSAlgorithm> jwsAlgorithms = new HashSet<>();

    public JwtDecoderBuilder jwsAlgorithm(JWSAlgorithm jwsAlgorithm) {
        return jwsAlgorithms(List.of(jwsAlgorithm));
    }

    public JwtDecoderBuilder jwsAlgorithms(Collection<JWSAlgorithm> jwsAlgorithms) {
        this.jwsAlgorithms.addAll(jwsAlgorithms);
        return this;
    }

    public JwtDecoderBuilder jwkSetUri(String jwkSetUri) {
        this.jwkSetUri = jwkSetUri;
        this.jwkSource = null;
        return this;
    }

    public JwtDecoderBuilder jwkSource(JWKSource<SecurityContext> jwkSource) {
        this.jwkSource = jwkSource;
        this.jwkSetUri = null;
        return this;
    }

    public JwtDecoder build() {
        NimbusJwtDecoder decoder;
        if (jwkSource != null) {
            decoder = createJwkSourceBasedDecoder();
        } else {
            decoder = createIssuerOrJwkSetBasedDecoder();
        }

        var validators = new ArrayList<OAuth2TokenValidator<Jwt>>();
        validators.add(JwtValidators.createDefault());

        if(issuer != null) {
            validators.add(new JwtIssuerValidator(issuer));
        }

        if(audience != null) {
            validators.add(new JwtClaimValidator<List<String>>(JwtClaimNames.AUD, aud -> aud != null && !Collections.disjoint(aud, audience)));
        }

        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validators));
        return decoder;
    }

    private NimbusJwtDecoder createJwkSourceBasedDecoder() {
        var processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(jwsAlgorithms, jwkSource));
        processor.setJWTClaimsSetVerifier((claimsSet, context) -> {});
        return new NimbusJwtDecoder(processor);
    }

    private NimbusJwtDecoder createIssuerOrJwkSetBasedDecoder() {
        JwkSetUriJwtDecoderBuilder decoderBuilder;
        if(jwkSetUri != null) {
            decoderBuilder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri);
        } else if(issuer != null) {
            decoderBuilder = NimbusJwtDecoder.withIssuerLocation(issuer);
        } else {
            throw new IllegalStateException(
                    "Neither jwkSetUri nor issuer are provided. Can not construct a JWT decoder.");
        }
        for (JWSAlgorithm jwsAlgorithm : jwsAlgorithms) {
            decoderBuilder.jwsAlgorithm(SignatureAlgorithm.from(jwsAlgorithm.getName()));
        }
        return decoderBuilder.build();
    }
}
