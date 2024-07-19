package com.contentgrid.tokenmonger.web;


import com.contentgrid.tokenmonger.oauth2.OAuth2ServerConfiguration;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequiredArgsConstructor
public class HomeController {

    private final List<OAuth2ServerConfiguration> servers;

    @GetMapping
    public ModelAndView root() {
        return new ModelAndView("root", Map.of(
                "servers", servers
        ));
    }

}
