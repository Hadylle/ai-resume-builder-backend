package com.example.ai_resume_builder.request;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignupRequest {

    private String email;
    private String password;
    private String firstName;
    private String lastName;


}
