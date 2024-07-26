package com.contentgrid.tokenmonger.application;

import java.util.List;
import lombok.NonNull;
import lombok.Value;

@Value
public class Application {
    @NonNull
    String applicationId;

    @NonNull
    List<String> domains;
}
