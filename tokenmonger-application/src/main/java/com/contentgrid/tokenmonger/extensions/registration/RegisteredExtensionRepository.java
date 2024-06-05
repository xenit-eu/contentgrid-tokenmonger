package com.contentgrid.tokenmonger.extensions.registration;

import java.util.Optional;

public interface RegisteredExtensionRepository {
    Optional<RegisteredExtension> findByResourceUri(String resourceUri);

    Optional<RegisteredExtension> findByClientId(String clientId);

    void save(RegisteredExtension extension);
}
