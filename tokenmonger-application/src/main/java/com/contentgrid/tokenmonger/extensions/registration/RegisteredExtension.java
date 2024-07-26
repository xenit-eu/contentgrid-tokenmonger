package com.contentgrid.tokenmonger.extensions.registration;

import java.util.Set;
import lombok.Builder;
import lombok.Value;

@Builder
@Value
public class RegisteredExtension {
    String extensionId;

    Set<String> resourceUris;
}
