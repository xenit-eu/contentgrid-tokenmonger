package com.contentgrid.tokenmonger.application;

import java.net.URI;
import java.util.Optional;

public interface ApplicationRepository {
    public Optional<Application> findByUri(URI uri);
}
