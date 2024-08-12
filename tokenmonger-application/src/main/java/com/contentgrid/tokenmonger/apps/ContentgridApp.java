package com.contentgrid.tokenmonger.apps;

import com.contentgrid.configuration.applications.ApplicationId;
import java.util.Set;
import lombok.NonNull;
import lombok.Value;

@Value
public class ContentgridApp {
    @NonNull
    ApplicationId applicationId;

    @NonNull
    Set<String> domains;
}
