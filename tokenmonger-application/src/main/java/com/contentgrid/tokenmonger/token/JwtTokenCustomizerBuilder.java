package com.contentgrid.tokenmonger.token;

import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtensionRepository;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.BiPredicate;
import java.util.function.Predicate;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class JwtTokenCustomizerBuilder {
    private final List<OAuth2TokenCustomizer<JwtEncodingContext>> customizers;

    public static JwtTokenCustomizerBuilder create() {
        return new JwtTokenCustomizerBuilder(List.of());
    }

    public JwtTokenCustomizerBuilder customizer(OAuth2TokenCustomizer<JwtEncodingContext> customizer) {
        var customizers = new ArrayList<>(this.customizers);
        customizers.add(customizer);
        return new JwtTokenCustomizerBuilder(customizers);
    }

    public JwtTokenCustomizerBuilder actorsFromAuthentication() {
        return customizer(new ActorsFromAuthentication());
    }

    public JwtTokenCustomizerBuilder expiryFromOriginalToken() {
        return customizer(new ExpiryFromOriginalToken());
    }

    public JwtTokenCustomizerBuilder mayActFromRegisteredClient(URL extensionIssuer, RegisteredExtensionRepository repository) {
        return customizer(new MayActFromRegisteredClient(extensionIssuer, repository));
    }

    public JwtTokenCustomizerBuilder subjectBasedOnOriginalToken() {
        return claimBasedOnOriginalToken((originalTokenClaims, tokenClaims) -> {
            var issuer = originalTokenClaims.getClaimAsString(JwtClaimNames.ISS);
            if(issuer == null) {
                issuer = "";
            }
            var subject = originalTokenClaims.getClaimAsString(JwtClaimNames.SUB);
            if(subject == null) {
                subject = "";
            }
            tokenClaims.subject(issuer+"#"+subject);
        });
    }

    public JwtTokenCustomizerBuilder claimBasedOnOriginalToken(BiConsumer<ClaimAccessor, JwtClaimsSet.Builder> configurer) {
        return customizer(new ClaimsBasedOnOriginalToken(configurer));
    }

    public JwtTokenCustomizerBuilder claimsFromOriginalToken(Predicate<String> predicate) {
        return claimsFromOriginalToken((claimName, claimValue) -> predicate.test(claimName));
    }

    public JwtTokenCustomizerBuilder claimsFromOriginalToken(BiPredicate<String, Object> predicate) {
        return claimBasedOnOriginalToken((claimAccessor, builder) -> {
            claimAccessor.getClaims().forEach((name, value) -> {
                if(predicate.test(name, value)) {
                    builder.claim(name, value);
                }
            });
        });
    }

    public OAuth2TokenCustomizer<JwtEncodingContext> build() {
        return context -> customizers.forEach(customizer -> customizer.customize(context));
    }
}
