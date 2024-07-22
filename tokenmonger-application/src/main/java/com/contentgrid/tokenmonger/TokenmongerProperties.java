package com.contentgrid.tokenmonger;

import com.contentgrid.tokenmonger.validation.IssuerOrJwkSetUriNotEmpty;
import com.nimbusds.jose.JWSAlgorithm;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import java.util.Set;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties("contentgrid.tokenmonger")
@Data
@Validated
public class TokenmongerProperties {

    @Data
    public abstract static class IssuerProperties {
        Set<JWSAlgorithm> jwsAlgorithms = Set.of(JWSAlgorithm.RS256);
        public abstract String getIssuer();
    }

    @EqualsAndHashCode(callSuper = true)
    @Data
    public static class TokenEncoderProperties extends IssuerProperties {
        @NotEmpty
        @URL(regexp = "^[^?#]+$")
        private String issuer;
        @NotEmpty
        private String activeSigningKeys;
        private String retiredSigningKeys;

    }

    @Data
    @EqualsAndHashCode(callSuper = true)
    @IssuerOrJwkSetUriNotEmpty
    public static class TokenDecoderProperties extends IssuerProperties {
        @URL(regexp = "^[^?#]+$")
        private String issuer;

        @URL
        private String jwkSetUri;

        private List<String> audience;

    }

    @Valid
    @NotNull
    private TokenDecoderProperties userApplicationAccess;
    @Valid
    @NotNull
    private TokenDecoderProperties extensionIdentity;

    @Valid
    @NotNull
    private TokenmongerProperties.TokenEncoderProperties extensionApplicationAccess;
    @Valid
    @NotNull
    private TokenmongerProperties.TokenEncoderProperties userExtensionAccess;
    @Valid
    @NotNull
    private TokenmongerProperties.TokenEncoderProperties extensionDelegatedApplicationAccess;


}
