package com.contentgrid.tokenmonger;


import com.contentgrid.tokenmonger.application.Application;
import jakarta.validation.constraints.NotNull;
import java.util.HashMap;
import java.util.Map;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties("contentgrid.tokenmonger.applications")
@Data
@Validated
public class ApplicationRegistrationProperties {
    @NotNull
    private Map<String, Application> registration = new HashMap<>();
}
