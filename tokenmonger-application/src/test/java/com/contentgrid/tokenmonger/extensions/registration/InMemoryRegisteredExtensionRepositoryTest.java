package com.contentgrid.tokenmonger.extensions.registration;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import org.junit.jupiter.api.Test;

class InMemoryRegisteredExtensionRepositoryTest {
    @Test
    void registeredWithResourceUri() {
        var ext1 = RegisteredExtension.builder()
                        .extensionId("test-1")
                        .clientIds(Set.of())
                        .resourceUris(Set.of("http://example.com", "http://example.net/", "http://path.example/path1"))
                        .build();
        var ext2 = RegisteredExtension.builder()
                .extensionId("test-2")
                .clientIds(Set.of())
                .resourceUris(Set.of("http://path.example/path2"))
                .build();
        var repo = new InMemoryRegisteredExtensionRepository(ext1, ext2);

        assertThat(repo.findByResourceUri("http://example.com/abc")).hasValue(ext1);
        assertThat(repo.findByResourceUri("http://example.com")).hasValue(ext1);
        assertThat(repo.findByResourceUri("http://example.com/")).hasValue(ext1);
        assertThat(repo.findByResourceUri("http://example.net")).hasValue(ext1);
        assertThat(repo.findByResourceUri("http://example.net/")).hasValue(ext1);
        assertThat(repo.findByResourceUri("http://example.net/xyz")).hasValue(ext1);
        assertThat(repo.findByResourceUri("http://example.net/xyz/")).hasValue(ext1);
        assertThat(repo.findByResourceUri("http://path.example/path1")).hasValue(ext1);
        assertThat(repo.findByResourceUri("http://path.example/path1/subpath")).hasValue(ext1);
        assertThat(repo.findByResourceUri("http://path.example/path1/subpath/")).hasValue(ext1);
        assertThat(repo.findByResourceUri("http://path.example/path2/subpath")).hasValue(ext2);
    }

}