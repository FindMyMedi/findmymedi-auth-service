package com.findmymedi.user_auth_service.repository;

import com.findmymedi.user_auth_service.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Long> {
    Optional<User> findByWso2UserId(String wso2UserId);
}
