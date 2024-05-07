package com.contentgrid.tokenmonger;

import java.net.URI;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "contentgrid.tokenmonger.user-to-extension")
@Data
public class TokenMongerUserToExtensionProperties {
    private String jwkSetUri;
    private URI issuer;
    private String activeSigningKeys;
    private String retiredSigningKeys;
}


