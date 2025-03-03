package com.example.ai_resume_builder;

import com.example.ai_resume_builder.model.User;
import com.example.ai_resume_builder.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        String adminEmail = "admin@example.com";
        String adminPassword = "Admin@123";


        if (!userRepository.existsByEmail(adminEmail)) {
            User adminUser = new User(
                    adminEmail,
                    passwordEncoder.encode(adminPassword),
                    User.Role.ADMIN,
                    "Admin",
                    "User"
            );
            userRepository.save(adminUser);
            System.out.println("✅ ADMIN user created successfully!");
        } else {
            System.out.println("⚠️ ADMIN user already exists.");
        }
    }
}
