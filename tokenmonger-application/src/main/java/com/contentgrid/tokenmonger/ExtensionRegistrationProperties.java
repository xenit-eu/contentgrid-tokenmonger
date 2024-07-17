package com.contentgrid.tokenmonger;

import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtension;
import jakarta.validation.constraints.NotNull;
import java.util.HashMap;
import java.util.Map;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties("contentgrid.tokenmonger.user-extension-access")
@Data
@Validated
public class ExtensionRegistrationProperties {
    @NotNull
    private Map<String, RegisteredExtension> registration = new HashMap<>();
}
