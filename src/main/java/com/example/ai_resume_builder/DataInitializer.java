package com.example.ai_resume_builder;

import com.example.ai_resume_builder.model.Role;
import com.example.ai_resume_builder.model.User;
import com.example.ai_resume_builder.repository.RoleRepository;
import com.example.ai_resume_builder.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Collections;

@Component
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        String adminUsername = "admin";
        String adminEmail = "admin@example.com";
        String adminPassword = "Admin@123";

        // ✅ Ensure ADMIN role exists in the database
        Role adminRole = roleRepository.findByName(Role.ERole.ADMIN);
        if (adminRole == null) {
            adminRole = new Role(Role.ERole.ADMIN);
            roleRepository.save(adminRole);
        }

        // ✅ Check if ADMIN user already exists
        if (!userRepository.existsByUsername(adminUsername)) {
            User adminUser = new User(
                    adminUsername,
                    passwordEncoder.encode(adminPassword),
                    Collections.singleton(adminRole), // Set the role
                    adminEmail
            );
            userRepository.save(adminUser);
            System.out.println("✅ ADMIN user created successfully!");
        } else {
            System.out.println("⚠️ ADMIN user already exists.");
        }
    }
}
