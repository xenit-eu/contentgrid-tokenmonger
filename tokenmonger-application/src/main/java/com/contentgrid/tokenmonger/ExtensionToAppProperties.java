package com.contentgrid.tokenmonger;

import java.net.URI;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "contentgrid.tokenmonger.extension-to-app")
@Data
public class ExtensionToAppProperties {
    private URI issuer;
    private String activeSigningKeys;
    private String retiredSigningKeys;
}
