package com.contentgrid.tokenmonger.jwk.source;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSetCacheRefreshEvaluator;
import com.nimbusds.jose.jwk.source.JWKSetParseException;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSetUnavailableException;
import com.nimbusds.jose.proc.SecurityContext;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.ResourcePatternResolver;

/**
 * Loads JWKs from PEM-encoded private key files.
 *
 * There is a distinction made between active and retired signing keys
 */
@RequiredArgsConstructor
public class FilebasedJWKSetSource implements JWKSetSource<SecurityContext> {
    private final ResourcePatternResolver resourcePatternResolver;

    private final String activeSigningKeysPattern;
    private final String retiredSigningKeysPattern;

    @Override
    public JWKSet getJWKSet(JWKSetCacheRefreshEvaluator refreshEvaluator, long currentTime, SecurityContext context)
            throws KeySourceException {
        try {
            Map<String, JWK> keys = new LinkedHashMap<>();
            for (Resource signingKeyResource : resourcePatternResolver.getResources(activeSigningKeysPattern)) {
                var signingKey = createFromSigningKey(signingKeyResource, null);
                keys.put(signingKey.getKeyID(), signingKey);
            }
            for (Resource signingKeyResource : resourcePatternResolver.getResources(retiredSigningKeysPattern)) {
                var signingKey = createFromSigningKey(signingKeyResource, new Date(currentTime));
                // putIfAbsent, so we don't replace an active key with a retired key if it is matched by both patterns
                keys.putIfAbsent(signingKey.getKeyID(), signingKey);
            }
            return new JWKSet(new ArrayList<>(keys.values()));
        } catch (IOException e) {
            throw new JWKSetUnavailableException("Failed to load JWKs from file", e);
        } catch (JOSEException e) {
            throw new JWKSetParseException("Failed to load JWKs from keys", e);
        }
    }

    private static JWK createFromSigningKey(Resource resource, Date expirationTime) throws IOException, JOSEException {
        var jwk = JWK.parseFromPEMEncodedObjects(resource.getContentAsString(StandardCharsets.UTF_8));
        if(jwk instanceof RSAKey rsaKey) {
            return new RSAKey.Builder(rsaKey)
                    .keyIDFromThumbprint()
                    .keyUse(KeyUse.SIGNATURE)
                    .expirationTime(expirationTime)
                    .build();
        } else if(jwk instanceof ECKey ecKey) {
            return new ECKey.Builder(ecKey)
                    .keyIDFromThumbprint()
                    .keyUse(KeyUse.SIGNATURE)
                    .expirationTime(expirationTime)
                    .build();
        } else if(jwk instanceof OctetKeyPair octetKeyPair) {
            return new OctetKeyPair.Builder(octetKeyPair)
                    .keyIDFromThumbprint()
                    .keyUse(KeyUse.SIGNATURE)
                    .expirationTime(expirationTime)
                    .build();
        } else {
            throw new IllegalArgumentException("Unsupported JWK key type %s; use RSA, EC or OKP".formatted(jwk.getKeyType()));
        }
    }

    @Override
    public void close() throws IOException {

    }
}
