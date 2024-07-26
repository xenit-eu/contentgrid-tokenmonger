package com.contentgrid.tokenmonger.web.serialization;

import com.contentgrid.tokenmonger.oauth2.grants.GrantType;
import com.fasterxml.jackson.annotation.JsonValue;
import org.springframework.boot.jackson.JsonMixin;

@JsonMixin(GrantType.class)
public abstract class GrantTypeMixin {
    @JsonValue
    public abstract String getValue();
}
