package com.example.ai_resume_builder.repository;

import com.example.ai_resume_builder.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(Role.ERole name);

    boolean existsByName(Role.ERole name);
}
