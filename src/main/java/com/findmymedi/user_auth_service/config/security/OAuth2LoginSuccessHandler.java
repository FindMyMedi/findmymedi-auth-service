package com.findmymedi.user_auth_service.config.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    public OAuth2LoginSuccessHandler(@Value("${app.frontend.url}") String frontUrl){
        setDefaultTargetUrl(frontUrl);
    }
}
