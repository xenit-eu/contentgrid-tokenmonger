package com.contentgrid.tokenmonger.web.serialization;

import com.fasterxml.jackson.annotation.JsonValue;
import com.nimbusds.jose.jwk.JWKSet;
import java.util.Map;
import org.springframework.boot.jackson.JsonMixin;

@JsonMixin(JWKSet.class)

public abstract class JwkSetMixin {
    @JsonValue
    public abstract Map<String, Object> toJSONObject();

}
