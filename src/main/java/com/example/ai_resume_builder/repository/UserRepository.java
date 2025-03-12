package com.example.ai_resume_builder.repository;


import com.example.ai_resume_builder.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    boolean existsByEmail(String Email);
    Optional<User> findByEmail(String email);


    Optional<User> findBySub(String sub);
}