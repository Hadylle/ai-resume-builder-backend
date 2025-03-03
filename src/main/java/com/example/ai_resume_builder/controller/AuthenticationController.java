package com.example.ai_resume_builder.controller;

import com.example.ai_resume_builder.request.LoginRequest;
import com.example.ai_resume_builder.request.SignupRequest;
import com.example.ai_resume_builder.request.TokenRefreshRequest;
import com.example.ai_resume_builder.response.JwtResponse;
import com.example.ai_resume_builder.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationController(UserService userService, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        return userService.authenticateUser(loginRequest, authenticationManager);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        return userService.registerUser(signUpRequest);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<JwtResponse> refreshToken(@Valid @RequestBody TokenRefreshRequest request) throws Exception {
        return userService.refreshToken(request);
    }
}
