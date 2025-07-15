package com.example.ai_resume_builder.service;

import com.example.ai_resume_builder.JWT.JwtUtils;
import com.example.ai_resume_builder.model.User;
import com.example.ai_resume_builder.repository.UserRepository;
import com.example.ai_resume_builder.request.LoginRequest;
import com.example.ai_resume_builder.request.SignupRequest;
import com.example.ai_resume_builder.request.TokenRefreshRequest;
import com.example.ai_resume_builder.response.JwtResponse;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.*;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;

    private final CloudinaryService cloudinaryService;


    // Constructor-based injection
    public UserService(
            UserRepository userRepository,
            PasswordEncoder encoder,
            JwtUtils jwtUtils,
            CloudinaryService cloudinaryService) {
        this.userRepository = userRepository;
        this.encoder = encoder;
        this.jwtUtils = jwtUtils;
        this.cloudinaryService = cloudinaryService;
    }

    public ResponseEntity<?> authenticateUser(LoginRequest loginRequest, AuthenticationManager authenticationManager) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtils.generateJwtToken(authentication);
            String refreshToken = jwtUtils.generateRefreshToken(authentication);

            Optional<User> user = userRepository.findByEmail(loginRequest.getEmail());
            if (user.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("error", "User not found"));
            }

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


    public UserDetails loadUserBySub(String sub) throws UsernameNotFoundException {
        Optional<User> optionalUser = userRepository.findBySub(sub);
        if (optionalUser.isEmpty()) {
            throw new UsernameNotFoundException("User not found with sub: " + sub);
        }
        return optionalUser.get();
    }

    public ResponseEntity<?> uploadProfilePicture(MultipartFile file, String email) {
        try {
            // Upload file to Cloudinary
            String imageUrl = cloudinaryService.uploadFile(file);

            // Find user by email
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Update user's profile picture URL
            user.setProfilePictureUrl(imageUrl);
            userRepository.save(user);

            return ResponseEntity.ok(Map.of("message", "Profile picture updated", "url", imageUrl));

        } catch (IOException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "File upload failed: " + e.getMessage()));
        }
    }
    @Transactional
    public User completeUserProfile(String sub, User updatedUser) {
        // Find the user by sub
        User existingUser = userRepository.findBySub(sub)
                .orElseThrow(() -> new RuntimeException("User not found with sub: " + sub));

        if (updatedUser.getFirstName() != null) {
            existingUser.setFirstName(updatedUser.getFirstName());
        }
        if (updatedUser.getLastName() != null) {
            existingUser.setLastName(updatedUser.getLastName());
        }
        // Update the user's profile with the provided data
        if (updatedUser.getPhoneNumber() != null) {
            existingUser.setPhoneNumber(updatedUser.getPhoneNumber());
        }
        if (updatedUser.getAddress() != null) {
            existingUser.setAddress(updatedUser.getAddress());
        }
        if (updatedUser.getCity() != null) {
            existingUser.setCity(updatedUser.getCity());
        }
        if (updatedUser.getState() != null) {
            existingUser.setState(updatedUser.getState());
        }
        if (updatedUser.getPostalCode() != null) {
            existingUser.setPostalCode(updatedUser.getPostalCode());
        }
        if (updatedUser.getCountry() != null) {
            existingUser.setCountry(updatedUser.getCountry());
        }
        if (updatedUser.getDateOfBirth() != null) {
            existingUser.setDateOfBirth(updatedUser.getDateOfBirth());
        }
        if (updatedUser.getGender() != null) {
            existingUser.setGender(updatedUser.getGender());
        }
        if (updatedUser.getNationality() != null) {
            existingUser.setNationality(updatedUser.getNationality());
        }
        if (updatedUser.getPreferredContactMethod() != null) {
            existingUser.setPreferredContactMethod(updatedUser.getPreferredContactMethod());
        }
        if (updatedUser.getMaritalStatus() != null) {
            existingUser.setMaritalStatus(updatedUser.getMaritalStatus());
        }

        // Save the updated user to the database
        return userRepository.save(existingUser);
    }


}
