package com.contentgrid.tokenmonger.apps;

import java.net.URI;
import java.util.Optional;

public interface ContentgridAppRepository {
    public Optional<ContentgridApp> findByUri(URI uri);
}
