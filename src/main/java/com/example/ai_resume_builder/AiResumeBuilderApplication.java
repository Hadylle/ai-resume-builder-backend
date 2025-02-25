package com.example.ai_resume_builder;

import com.example.ai_resume_builder.model.Role;
import com.example.ai_resume_builder.model.User;
import com.example.ai_resume_builder.repository.RoleRepository;
import com.example.ai_resume_builder.repository.UserRepository;
import org.hibernate.mapping.Collection;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;

@SpringBootApplication
@EnableJpaRepositories

public class AiResumeBuilderApplication {

	public static void main(String[] args) {
		SpringApplication.run(AiResumeBuilderApplication.class, args);
	}

	@Bean
	CommandLineRunner initAdminUser(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
		return args -> {
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
		};
	}
}
