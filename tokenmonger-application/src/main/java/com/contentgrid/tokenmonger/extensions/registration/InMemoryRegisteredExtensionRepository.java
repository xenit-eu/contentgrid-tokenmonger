package com.contentgrid.tokenmonger.extensions.registration;

import java.net.URI;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Stream;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class InMemoryRegisteredExtensionRepository implements RegisteredExtensionRepository {

    private final Map<String, RegisteredExtension> byIdMap = new HashMap<>();
    private final Map<String, RegisteredExtension> resourceUriMap = new HashMap<>();

    public InMemoryRegisteredExtensionRepository(Collection<RegisteredExtension> registeredExtensions) {
        for (RegisteredExtension registeredExtension : registeredExtensions) {
            save(registeredExtension);
        }
    }

    public InMemoryRegisteredExtensionRepository(RegisteredExtension ...registeredExtensions) {
        this(List.of(registeredExtensions));
    }

    @Override
    public Optional<RegisteredExtension> findByResourceUri(String resourceUri) {
        return resourceUriParts(URI.create(resourceUri))
                .peek(u -> log.trace("Resource URI '{}' is also valid as '{}'", resourceUri, u))
                .flatMap(uri -> Stream.ofNullable(resourceUriMap.get(uri)))
                .findFirst();
    }

    @SneakyThrows
    private static Stream<String> resourceUriParts(URI uri) {
        var baseUriWithoutPath = new URI(uri.getScheme(), uri.getAuthority(), null, null, null);
        var baseUriWithPath = baseUriWithoutPath.resolve("/");
        return Stream.concat(
                        Stream.iterate(uri, u -> !u.equals(baseUriWithoutPath) && !u.equals(baseUriWithPath), u -> {
                            var currentDir = u.resolve(".");
                            if(!Objects.equals(currentDir, u)) {
                                return currentDir;
                            } else {
                                return u.resolve("..").resolve(".");
                            }
                        }),
                        Stream.of(baseUriWithoutPath, baseUriWithPath)
                )
                .map(URI::toASCIIString);
    }

    @Override
    public void save(RegisteredExtension extension) {
        try {
            tryRegister(byIdMap, extension.getExtensionId(), extension, (old) -> new IllegalArgumentException(
                    "An extension with id '%s' is already registered".formatted(old.getExtensionId())));

            extension.getResourceUris().forEach(resourceUri -> {
                var canonicalResourceUri = resourceUri.endsWith("/")?resourceUri:resourceUri+"/";
                tryRegister(resourceUriMap, resourceUri, extension, (old) -> new IllegalArgumentException(
                        "The extension with id '%s' is already using resource URI '%s'".formatted(old.getExtensionId(),
                                resourceUri)));
                tryRegister(resourceUriMap, canonicalResourceUri, extension, (old) -> new IllegalArgumentException(
                        "The extension with id '%s' is already using resource URI '%s'".formatted(old.getExtensionId(),
                                canonicalResourceUri)));
            });

        } catch(IllegalArgumentException ex) {
            // rollback all changes; remove registration for extension
            byIdMap.remove(extension.getExtensionId(), extension);
            extension.getResourceUris().forEach(resourceUri -> {
                resourceUriMap.remove(resourceUri, extension);
            });
            throw ex;
        }

    }

    private <X extends Exception> void tryRegister(Map<String, RegisteredExtension> map, String key, RegisteredExtension extension, Function<RegisteredExtension, X> error) throws X{
        var oldValue = map.putIfAbsent(key, extension);
        if(oldValue == extension) {
            return;
        }
        if(oldValue != null) {
            throw error.apply(oldValue);
        }
    }
}
