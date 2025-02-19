package com.example.ai_resume_builder.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class TokenRefreshRequest {
    @NotBlank
    private String refreshToken;

    public String getRefreshToken() {
        return refreshToken;
    }


    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
