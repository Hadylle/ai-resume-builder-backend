package com.example.ai_resume_builder.controller;

import com.example.ai_resume_builder.JWT.JwtUtils;
import com.example.ai_resume_builder.model.Role;
import com.example.ai_resume_builder.model.User;
import com.example.ai_resume_builder.request.LoginRequest;
import com.example.ai_resume_builder.request.SignupRequest;
import com.example.ai_resume_builder.request.TokenRefreshRequest;
import com.example.ai_resume_builder.response.JwtResponse;
import com.example.ai_resume_builder.response.MessageResponse;
import com.example.ai_resume_builder.response.TokenRefreshResponse;
import com.example.ai_resume_builder.repository.RoleRepository;
import com.example.ai_resume_builder.repository.UserRepository;
import com.example.ai_resume_builder.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    UserService userService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        String refreshToken = jwtUtils.generateRefreshToken(authentication);

        // Get the user from the database
        User user = userRepository.findByUsername(loginRequest.getUsername());
        if (user == null) {
            throw new RuntimeException("Error: User not found");
        }

        // Extract roles from user
        List<String> roles = user.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        // Return response with user details
        return ResponseEntity.ok(new JwtResponse(
                jwt,
                refreshToken,
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                roles
        ));
    }


    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) throws Exception {
        /*if (!roleRepository.existsByName(Role.ERole.USER)) {
            roleRepository.save(new Role(Role.ERole.USER));
        }
        if (!roleRepository.existsByName(Role.ERole.ADMIN)) {
            roleRepository.save(new Role(Role.ERole.ADMIN));
        }*/

        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            throw new Exception("Error: Username is already taken!");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new Exception("Error: Email is already in use!");
        }

        Set<Role> roles = new HashSet<>();
        if (signUpRequest.getRole() == null || signUpRequest.getRole().isEmpty()) {
            Role userRole = roleRepository.findByName(Role.ERole.USER);
            if (userRole == null) {
                throw new RuntimeException("Error: Role USER is not found.");
            }
            roles.add(userRole);
        } else {
            switch (signUpRequest.getRole().toLowerCase()) {
                case "admin":
                    Role adminRole = roleRepository.findByName(Role.ERole.ADMIN);
                    if (adminRole == null) {
                        throw new RuntimeException("Error: Role ADMIN is not found.");
                    }
                    roles.add(adminRole);
                    break;
                case "USER":
                    Role userRole = roleRepository.findByName(Role.ERole.USER);
                    if (userRole == null) {
                        throw new RuntimeException("Error: Role USER is not found.");
                    }
                    roles.add(userRole);
                    break;
                default:
                    throw new Exception("Error: Role not recognized.");
            }
        }
        System.out.println("START");
        User user = new User(signUpRequest.getUsername(), encoder.encode(signUpRequest.getPassword()), roles, signUpRequest.getEmail());
        userRepository.save(user);
        System.out.println("END");
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("message", "Success"));

    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody TokenRefreshRequest request) throws Exception {
        String requestRefreshToken = request.getRefreshToken();

        if (!jwtUtils.validateJwtToken(requestRefreshToken)) {
            throw new Exception("Invalid refresh token");
        }

        String username = jwtUtils.getUserNameFromJwtToken(requestRefreshToken);
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new RuntimeException("Error: User not found");
        }

        UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.getAuthorities() // Ensure you have correct roles/authorities
        );

        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());


        String jwt = jwtUtils.generateJwtToken(authentication);
        String refreshToken = jwtUtils.generateRefreshToken(authentication);

        List<String> roles = user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt, refreshToken, user.getId(), user.getUsername(), user.getEmail(),roles));
    }
}
