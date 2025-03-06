package com.example.ai_resume_builder.controller;

import com.example.ai_resume_builder.model.User;
import com.example.ai_resume_builder.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/role")
public class RoleBasedAccessController {

    @Autowired
    private UserService userService;

    @GetMapping("/admin")
    public ResponseEntity<String> adminAccess() {
        var x = "dzovi";
        System.out.println(x);
        return ResponseEntity.ok("Welcome Admin");
    }


    @GetMapping("/user")
    public ResponseEntity<String> userAccess() {
        return ResponseEntity.ok("Welcome Admin");
    }
}

