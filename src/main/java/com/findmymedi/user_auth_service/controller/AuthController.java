package com.findmymedi.user_auth_service.controller;

import com.findmymedi.user_auth_service.dto.CurrentUserResponseDto;
import com.findmymedi.user_auth_service.dto.UserRequestDto;
import com.findmymedi.user_auth_service.entity.RoleType;
import com.findmymedi.user_auth_service.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;


@RestController
@RequestMapping("/auth")
public class AuthController {

    @Value("${app.wso2.signup-url}")
    private String wso2SignupUrl;

    private final UserService userService;

    public AuthController(UserService userService){
        this.userService = userService;
    }

//    @GetMapping("/register")
//    public void register(HttpServletResponse response) throws IOException {
//        response.sendRedirect(wso2SignupUrl);
//    }

    @GetMapping("/login-success")
    public ResponseEntity<String> loginSuccess(@AuthenticationPrincipal OidcUser oidcUser) {

//        UserRequestDto userRequestDto = new UserRequestDto();
//
//        userRequestDto.setWso2UserId(oidcUser.getSubject());
//        userRequestDto.setEmail(oidcUser.getEmail());
//        userRequestDto.setFullName(oidcUser.getFullName());
//        userRequestDto.setRole(RoleType.USER);
//
//        userService.createUser(userRequestDto);

        return ResponseEntity.ok("Login successful");
    }

    @GetMapping("/login-failure")
    public ResponseEntity<String> loginFailure() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Login failed");
    }

    @GetMapping("/current-user")
    public ResponseEntity<?> currentUser(@AuthenticationPrincipal OidcUser oidcUser){
        if (oidcUser == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Not logged in");
        }

        CurrentUserResponseDto currentUser = userService.getCurrentUser(oidcUser);

        return ResponseEntity.ok(currentUser);
    }

}
