package com.findmymedi.user_auth_service.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.Set;

@Data
public class UserRequestDto {

    @NotEmpty
    private String wso2UserId;

    @NotEmpty
    private String fullName;

    @Email
    private String email;

    private Set<String> roles;
}
