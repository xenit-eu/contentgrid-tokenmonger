package com.contentgrid.tokenmonger.web;

import com.contentgrid.tokenmonger.oauth2.grants.GrantType;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import lombok.Builder;
import lombok.Value;

@Builder(toBuilder = true)
@Value
@JsonInclude(Include.NON_NULL)
public class OAuth2ServerMetadata {
    String issuer;

    @JsonProperty("token_endpoint")
    String tokenEndpoint;

    @JsonProperty("jwks_uri")
    String jwksUri;

    @JsonProperty("grant_types_supported")
    List<GrantType> grantTypesSupported;

    @JsonProperty("token_endpoint_auth_methods_supported")
    @Builder.Default
    List<String> tokenEndpointAuthMethodsSupported = List.of("none");

}
