package com.contentgrid.tokenmonger;

import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtension;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("contentgrid.tokenmonger.extension")
@Data
public class ExtensionProperties {
    private URI issuer;
    private Map<String, RegisteredExtension> registration = new HashMap<>();
    private String activeSigningKeys;
    private String retiredSigningKeys;
}
