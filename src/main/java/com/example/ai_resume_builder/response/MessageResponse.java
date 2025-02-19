package com.example.ai_resume_builder.response;

import lombok.Getter;

@Getter
public class MessageResponse {

    private String message;

    public MessageResponse(String message) {
        this.message = message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
