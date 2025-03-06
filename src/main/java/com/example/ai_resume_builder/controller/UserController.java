package com.example.ai_resume_builder.controller;

import com.example.ai_resume_builder.model.User;
import com.example.ai_resume_builder.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserService userService;


    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/upload-profile-picture")
    public ResponseEntity<?> uploadProfilePicture(@RequestParam("file") MultipartFile file,
                                                  @RequestParam("email") String email) {
        return userService.uploadProfilePicture(file, email);
    }
    @GetMapping
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }



    @PostMapping
    public ResponseEntity<User> createUser(@RequestBody User user) {
        return ResponseEntity.ok(userService.saveUser(user));
    }
}
