package com.contentgrid.tokenmonger.authentication;

import lombok.experimental.UtilityClass;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

@UtilityClass
public class AuthorizationGrantExtensions {

    public static final AuthorizationGrantType CONTENTGRID_EXTENSION_TOKEN_GRANT_TYPE = new AuthorizationGrantType("https://contentgrid.cloud/oauth2/grant/extension-token");
}
