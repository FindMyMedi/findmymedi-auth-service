package com.findmymedi.user_auth_service.entity;

import jakarta.persistence.*;

import java.util.UUID;

@Entity
@Table(name = "user_role")
public class UserRole {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private UUID id;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    @ManyToOne
    @JoinColumn(name = "role_id")
    private UserRole userRole;
    
}
