package com.contentgrid.tokenmonger.clientregistration;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

@Slf4j
public class InMemoryRegisteredClientRepository implements RegisteredClientRepository{
    private final org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository delegate;

    public static final String RESOURCE_URI_SETTING = "resource-uris";

    private final Map<String, String> resourceUriToId = new HashMap<>();

    public InMemoryRegisteredClientRepository(List<RegisteredClient> clients) {
        this.delegate = new org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository(clients);
        clients.forEach(this::registerResourceUri);
    }

    @Override
    public RegisteredClient findByResourceUri(String resourceUri) {
        return resourceUriParts(URI.create(resourceUri))
                .peek(u -> log.trace("Resource URI '{}' is also valid as '{}'", resourceUri, u))
                .flatMap(uri -> Stream.ofNullable(resourceUriToId.get(uri)))
                .findFirst()
                .map(this::findById)
                .orElse(null);
    }

    private static Stream<String> resourceUriParts(URI uri) {
        return Stream.iterate(uri, u -> !u.equals(u.resolve("..")), u -> {
                    var currentDir = u.resolve(".");
                    if(!Objects.equals(currentDir, u)) {
                        return currentDir;
                    } else {
                        return u.resolve("..").resolve(".");
                    }
                })
                .map(URI::toASCIIString);
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        delegate.save(registeredClient);
        registerResourceUri(registeredClient);
    }

    private void registerResourceUri(RegisteredClient registeredClient) {
        registeredClient.getClientSettings().<List<String>>getSetting(RESOURCE_URI_SETTING)
                .forEach(resourceUri -> {
                    var existingId = resourceUriToId.putIfAbsent(resourceUri, registeredClient.getId());
                    if(existingId != null) {
                        throw new IllegalStateException("Multiple clients are registered with the same resource URI '%s': %s and %s".formatted(resourceUri, existingId, registeredClient.getId()));
                    }
                });
    }

    @Override
    public RegisteredClient findById(String id) {
        return delegate.findById(id);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return delegate.findByClientId(clientId);
    }
}
