package com.example.ai_resume_builder;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EnableJpaRepositories

public class AiResumeBuilderApplication {

	public static void main(String[] args) {
		SpringApplication.run(AiResumeBuilderApplication.class, args);
	}


}
