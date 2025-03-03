package com.example.ai_resume_builder.service;

import com.example.ai_resume_builder.JWT.JwtUtils;
import com.example.ai_resume_builder.model.User;
import com.example.ai_resume_builder.repository.UserRepository;
import com.example.ai_resume_builder.request.LoginRequest;
import com.example.ai_resume_builder.request.SignupRequest;
import com.example.ai_resume_builder.request.TokenRefreshRequest;
import com.example.ai_resume_builder.response.JwtResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;

    // Constructor-based injection
    public UserService(
            UserRepository userRepository,
            PasswordEncoder encoder,
            JwtUtils jwtUtils
    ) {
        this.userRepository = userRepository;
        this.encoder = encoder;
        this.jwtUtils = jwtUtils;
    }

    public ResponseEntity<?> authenticateUser(LoginRequest loginRequest, AuthenticationManager authenticationManager) {
        System.out.println("Starting authentication process for user: " + loginRequest.getEmail());

        try {
            System.out.println("Authenticating user with email: " + loginRequest.getEmail());
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            System.out.println("User authenticated successfully: " + authentication.getName());
            String jwt = jwtUtils.generateJwtToken(authentication);
            String refreshToken = jwtUtils.generateRefreshToken(authentication);
            System.out.println("Generated JWT: " + jwt);
            System.out.println("Generated Refresh Token: " + refreshToken);

            Optional<User> user = userRepository.findByEmail(loginRequest.getEmail());
            System.out.println("Retrieved user from repository: " + user);

            if (user.isEmpty()) {
                System.out.println("User not found for email: " + loginRequest.getEmail());
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("error", "User not found"));
            }
            System.out.println("User role: " + user.get().getRole());
            List<String> roles = Collections.singletonList(user.get().getRole().name());

            return ResponseEntity.ok(new JwtResponse(
                    jwt,
                    refreshToken,
                    user.get().getId(),
                    user.get().getEmail(),
                    user.get().getRole().name()
            ));

        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid email or password"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "An error occurred: " + e.getMessage()));
        }
    }

    public ResponseEntity<?> registerUser(@Valid SignupRequest signUpRequest) {
        try {
            if (userRepository.existsByEmail(signUpRequest.getEmail())) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("error", "Email is already in use!"));
            }

            User user = new User(
                    signUpRequest.getEmail(),
                    encoder.encode(signUpRequest.getPassword()),
                    User.Role.USER, // Default to USER role
                    signUpRequest.getFirstName(),
                    signUpRequest.getLastName()
            );
            userRepository.save(user);

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(Map.of("message", "User registered successfully"));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "An error occurred: " + e.getMessage()));
        }
    }

    public ResponseEntity<JwtResponse> refreshToken(TokenRefreshRequest request) throws Exception {
        String requestRefreshToken = request.getRefreshToken();

        if (!jwtUtils.validateJwtToken(requestRefreshToken)) {
            throw new Exception("Invalid refresh token");
        }

        String email = jwtUtils.getUserNameFromJwtToken(requestRefreshToken);
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get(); // Now this is your entity directly

            // Create an Authentication object directly from your User entity
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    user, // Pass the user entity instead of a new UserDetails object
                    null,
                    user.getAuthorities()
            );

            String jwt = jwtUtils.generateJwtToken(authentication);
            String refreshToken = jwtUtils.generateRefreshToken(authentication);

            return ResponseEntity.ok(new JwtResponse(
                    jwt, refreshToken, user.getId(), user.getEmail(), user.getRole().name()));
        } else {
            throw new RuntimeException("User not found!");
        }
    }



    @Override
    public User loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isEmpty()) {
            throw new UsernameNotFoundException("User not found: " + email);
        }
        return optionalUser.get();
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public User getUserByEmail(String email) {
        Optional<User> user = userRepository.findByEmail(email);
        return user.get();
    }

    public User saveUser(User user) {
        return userRepository.save(user);
    }

    public boolean authenticateUserForRole(String email, String password, User.Role role) {
        System.out.println("Authenticating user: " + email + " for role: " + role);
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isPresent()) {
            System.out.println("User found in database");
            User user = userOptional.get();
            boolean passwordMatches = encoder.matches(password, user.getPassword());
            boolean roleMatches = user.getRole().equals(role);

            System.out.println("Password matches: " + passwordMatches);
            System.out.println("Role matches: " + roleMatches);

            return passwordMatches && roleMatches;
        } else {
            System.out.println("User not found in database");
            return false;
        }
    }


}
