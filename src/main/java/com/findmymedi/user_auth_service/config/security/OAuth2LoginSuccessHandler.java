package com.findmymedi.user_auth_service.config.security;

import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    public OAuth2LoginSuccessHandler(){
        setDefaultTargetUrl("http://localhost:4200/");
    }
}
