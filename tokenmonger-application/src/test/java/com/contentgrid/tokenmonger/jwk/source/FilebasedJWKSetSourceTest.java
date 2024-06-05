package com.contentgrid.tokenmonger.jwk.source;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.nimbusds.jose.jwk.JWK;
import java.nio.charset.StandardCharsets;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

class FilebasedJWKSetSourceTest {

    @Test
    @SneakyThrows
    void testGetJWKSet() {
        var activeKey = CryptoTestUtils.createKeyPair("RSA", 2048);
        var activeResource = CryptoTestUtils.toPrivateKeyResource(activeKey);
        var retiredKey = CryptoTestUtils.createKeyPair("RSA", 2048);
        var retiredResource = CryptoTestUtils.toPrivateKeyResource(retiredKey);
        var resourcePatternResolver = MockResourcePatternResolver.builder()
                .resource("file:/keys/active.pem", activeResource)
                .resource("file:/keys/retired.pem", retiredResource)
                .build();
        var filebasedJWKSetSource = new FilebasedJWKSetSource(resourcePatternResolver, "file:/keys/active.pem",
                "file:/keys/retired.pem");

        var jwkSet = filebasedJWKSetSource.getJWKSet(null, System.currentTimeMillis(), null);
        var activeJWK = JWK.parseFromPEMEncodedObjects(activeResource.getContentAsString(StandardCharsets.UTF_8));
        var retiredJWK = JWK.parseFromPEMEncodedObjects(retiredResource.getContentAsString(StandardCharsets.UTF_8));

        assertEquals(2, jwkSet.getKeys().size());
        assertNotNull(jwkSet.getKeyByKeyId(activeJWK.computeThumbprint().toString()));
        assertNotNull(jwkSet.getKeyByKeyId(retiredJWK.computeThumbprint().toString()));
    }

}