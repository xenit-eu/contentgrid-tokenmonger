package com.contentgrid.tokenmonger;

import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class TestController {

    @GetMapping("/user-info")
    @ResponseBody
    Map<String, Object> getUserInfo(@AuthenticationPrincipal JwtAuthenticationToken authentication) {
        return authentication.getTokenAttributes();
    }

}
