package com.example.ai_resume_builder.service;

import com.example.ai_resume_builder.JWT.JwtUtils;
import com.example.ai_resume_builder.model.Role;
import com.example.ai_resume_builder.model.User;
import com.example.ai_resume_builder.repository.RoleRepository;
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
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;

    // Constructor-based injection
    public UserService(
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder encoder,
            JwtUtils jwtUtils
    ) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
        this.jwtUtils = jwtUtils;
    }

    public ResponseEntity<?> authenticateUser(LoginRequest loginRequest, AuthenticationManager authenticationManager) {
        System.out.println("Starting authentication process for user: " + loginRequest.getUsername());

        try {
            System.out.println("Authenticating user with username: " + loginRequest.getUsername());
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            System.out.println("User authenticated successfully: " + authentication.getName());
            String jwt = jwtUtils.generateJwtToken(authentication);
            String refreshToken = jwtUtils.generateRefreshToken(authentication);
            System.out.println("Generated JWT: " + jwt);
            System.out.println("Generated Refresh Token: " + refreshToken);

            User user = userRepository.findByUsername(loginRequest.getUsername());
            System.out.println("Retrieved user from repository: " + user);

            if (user == null) {
                System.out.println("User not found for username: " + loginRequest.getUsername());
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("error", "User not found"));
            }
            System.out.println("User roles: " + user.getAuthorities());
            List<String> roles = user.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());

            return ResponseEntity.ok(new JwtResponse(
                    jwt,
                    refreshToken,
                    user.getId(),
                    user.getUsername(),
                    user.getEmail(),
                    roles
            ));

        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid username or password"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "An error occurred: " + e.getMessage()));
        }
    }

    public ResponseEntity<?> registerUser(@Valid SignupRequest signUpRequest) {
        try {
            if (userRepository.existsByUsername(signUpRequest.getUsername())) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("error", "Username is already taken!"));
            }

            if (userRepository.existsByEmail(signUpRequest.getEmail())) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("error", "Email is already in use!"));
            }
            Role userRole = roleRepository.findByName(Role.ERole.USER);
            if (userRole == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("error", "Role USER is not found in the database."));
            }
            Set<Role> roles = new HashSet<>();
            roles.add(userRole);

            User user = new User(signUpRequest.getUsername(), encoder.encode(signUpRequest.getPassword()), roles, signUpRequest.getEmail());
            userRepository.save(user);

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(Map.of("message", "Success"));

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

        String username = jwtUtils.getUserNameFromJwtToken(requestRefreshToken);
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new RuntimeException("Error: User not found");
        }

        UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.getAuthorities()
        );

        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        String jwt = jwtUtils.generateJwtToken(authentication);
        String refreshToken = jwtUtils.generateRefreshToken(authentication);

        List<String> roles = user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt, refreshToken, user.getId(), user.getUsername(), user.getEmail(), roles));
    }

    @Override
    public User loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }
        return user;
    }


    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public User saveUser(User user) {
        return userRepository.save(user);
    }



}
