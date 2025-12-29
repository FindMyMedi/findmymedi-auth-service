package com.findmymedi.user_auth_service.repository;

import com.findmymedi.user_auth_service.entity.Role;
import com.findmymedi.user_auth_service.entity.RoleType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role,Long> {
    Optional<Role> findByRoleName(RoleType roleName);

}
