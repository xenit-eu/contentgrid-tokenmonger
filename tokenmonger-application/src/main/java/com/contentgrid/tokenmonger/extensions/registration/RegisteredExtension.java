package com.contentgrid.tokenmonger.extensions.registration;

import java.util.Set;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.Value;

@Builder
@Value
public class RegisteredExtension {
    String extensionId;

    Set<String> clientIds;

    Set<String> resourceUris;
}
