package com.findmymedi.user_auth_service.dto;

import com.findmymedi.user_auth_service.entity.RoleType;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;


@Data
public class UserRequestDto {

    @NotEmpty
    private String wso2UserId;

    @NotEmpty
    private String fullName;

    @Email
    private String email;

    private RoleType role;
}
