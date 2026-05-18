package com.contentgrid.tokenmonger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import com.contentgrid.configuration.applications.ApplicationId;
import com.contentgrid.tokenmonger.apps.ContentgridAppRepository;
import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.KubernetesClient;
import java.net.URI;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.k3s.K3sContainer;
import org.testcontainers.utility.DockerImageName;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "spring.main.cloud-platform=kubernetes",
            "spring.profiles.active=test",
            "management.endpoints.web.exposure.include=*",
            "management.prometheus.metrics.export.enabled=true", //bootRun profile disables metrics, which is fine for other tests but should be overridden here
            "management.server.port=0" // random, different port from main port
        },
        classes = {AbstractTokenmongerApplicationIntegrationTest.TestConfig.class})
@Testcontainers
class TokenMongerKubernetesIntegrationTest extends AbstractTokenmongerApplicationIntegrationTest {

    @Autowired
    private TestRestTemplate rest;
    @Value("${local.management.port}")
    int managementPort;

    @Container
    private static final K3sContainer k3sContainer = new K3sContainer(DockerImageName.parse("rancher/k3s:latest"));

    @DynamicPropertySource
    static void configureKubernetesProperties(DynamicPropertyRegistry propertyRegistry) {
        var kubernetesConfig = Config.fromKubeconfig(k3sContainer.getKubeConfigYaml());
        propertyRegistry.add("spring.cloud.kubernetes.client.master-url", kubernetesConfig::getMasterUrl);
        propertyRegistry.add("spring.cloud.kubernetes.client.ca-cert-data", kubernetesConfig::getCaCertData);
        propertyRegistry.add("spring.cloud.kubernetes.client.client-cert-data", kubernetesConfig::getClientCertData);
        propertyRegistry.add("spring.cloud.kubernetes.client.client-key-data", kubernetesConfig::getClientKeyData);
        propertyRegistry.add("spring.cloud.kubernetes.client.client-key-algo", kubernetesConfig::getClientKeyAlgo);
        propertyRegistry.add("spring.cloud.kubernetes.client.client-key-passphrase",
                kubernetesConfig::getClientKeyPassphrase);

    }

    @BeforeAll
    static void seedConfiguration(@Autowired KubernetesClient kubernetesClient) {
        kubernetesClient.configMaps()
                .resource(new ConfigMapBuilder()
                        .withNewMetadata()
                        .withNamespace("default")
                        .withGenerateName("tokenmonger-")
                        .addToLabels("app.contentgrid.com/service-type", "gateway")
                        .addToLabels("app.contentgrid.com/application-id", "abc")
                        .endMetadata()
                        .addToData("contentgrid.routing.domains", "abc.contentgrid.example,def.contentgrid.example")
                        .build())
                .create();

    }

    @Test
    void startupAndDiscoversConfiguration(
            @Autowired ContentgridAppRepository appRepository
    ) {

        await().atMost(5, TimeUnit.SECONDS).untilAsserted(() -> {
            assertThat(appRepository.findByUri(URI.create("https://abc.contentgrid.example/x/y/z"))).hasValueSatisfying(
                    app -> {
                        assertThat(app.getApplicationId()).isEqualTo(ApplicationId.from("abc"));
                        assertThat(app.getDomains()).containsExactlyInAnyOrder(
                                "abc.contentgrid.example",
                                "def.contentgrid.example"
                        );
                    });
        });

    }

    @Test
    void prometheusEndpointIsPublic() {
        ResponseEntity<String> resp = rest.getForEntity("http://localhost:" + managementPort + "/actuator/prometheus", String.class);
        assertThat(resp.getStatusCode().is2xxSuccessful()).isTrue();
    }


}
