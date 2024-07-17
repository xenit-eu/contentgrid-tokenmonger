package com.contentgrid.tokenmonger.extensions.registration;

import java.util.Optional;

public interface RegisteredExtensionRepository {
    Optional<RegisteredExtension> findByResourceUri(String resourceUri);

    void save(RegisteredExtension extension);
}
