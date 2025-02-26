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


}
