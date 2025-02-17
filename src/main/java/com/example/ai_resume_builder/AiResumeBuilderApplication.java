package com.example.ai_resume_builder;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication(exclude = SecurityAutoConfiguration.class)
public class AiResumeBuilderApplication {

	public static void main(String[] args) {
		SpringApplication.run(AiResumeBuilderApplication.class, args);
	}

}
