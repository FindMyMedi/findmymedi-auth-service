package com.findmymedi.user_auth_service.controller;

import com.findmymedi.user_auth_service.dto.UserRequestDto;
import com.findmymedi.user_auth_service.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashSet;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService){
        this.userService = userService;
    }

    @GetMapping("/login-success")
    public ResponseEntity<String> loginSuccess(@AuthenticationPrincipal OidcUser oidcUser) {

        UserRequestDto userRequestDto = new UserRequestDto();

        userRequestDto.setWso2UserId(oidcUser.getSubject());
        userRequestDto.setEmail(oidcUser.getEmail());
        userRequestDto.setFullName(oidcUser.getFullName());
        userRequestDto.setRoles(new HashSet<>(oidcUser.getClaimAsStringList("roles")));

        userService.createUser(userRequestDto);

        return ResponseEntity.ok("Login successful");
    }


}
