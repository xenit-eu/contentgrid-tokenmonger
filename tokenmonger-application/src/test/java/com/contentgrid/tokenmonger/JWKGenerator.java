package com.contentgrid.tokenmonger;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;

@UtilityClass
class JWKGenerator {

    @SneakyThrows
    JWK createRandomJWK() {
        return new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyIDFromThumbprint(true)
                .generate();
    }

}
