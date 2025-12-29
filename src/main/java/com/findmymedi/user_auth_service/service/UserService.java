package com.findmymedi.user_auth_service.service;

import com.findmymedi.user_auth_service.dto.UserRequestDto;
import com.findmymedi.user_auth_service.entity.*;
import com.findmymedi.user_auth_service.repository.RoleRepository;
import com.findmymedi.user_auth_service.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public UserService(UserRepository userRepository,RoleRepository roleRepository){
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    public void createUser(UserRequestDto userRequestDto){
        if(userRepository.findByWso2UserId(userRequestDto.getWso2UserId()).isPresent()){
            throw new RuntimeException("User already exists");
        }

        User user = new User();
        user.setWso2UserId(userRequestDto.getWso2UserId());
        user.setFullName(userRequestDto.getFullName());
        user.setEmail(userRequestDto.getEmail());
        user.setStatus(UserStatus.ACTIVE);

        Set<UserRole> userRoles = new HashSet<>();
        for (String roleName : userRequestDto.getRoles()) {
            Role role = getOrCreateRole(roleName);
            UserRole userRole = new UserRole();
            userRole.setUser(user);
            userRole.setRole(role);
            userRoles.add(userRole);
        }

        user.setUserRoles(userRoles);
        userRepository.save(user);
    }

    private Role getOrCreateRole(String roleName) {
        RoleType roleType = RoleType.valueOf(roleName.toUpperCase());

        return roleRepository.findByRoleName(roleType)
                .orElseGet(() -> roleRepository.save(new Role(null,roleType)));
    }

}
