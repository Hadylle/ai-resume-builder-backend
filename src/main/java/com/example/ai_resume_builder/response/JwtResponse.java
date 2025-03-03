package com.example.ai_resume_builder.response;

import com.example.ai_resume_builder.model.User;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.UUID;

@Data
public class JwtResponse {
    private String token;
    private String refreshToken;
    private String type = "Bearer";
    private UUID id;
    private String email;
    private String role;


    public JwtResponse(String accessToken, String refreshToken, UUID id, String email, String role) {
        this.token = accessToken;
        this.refreshToken = refreshToken;
        this.id = id;
        this.email = email;
        this.role = role;
    }

}

