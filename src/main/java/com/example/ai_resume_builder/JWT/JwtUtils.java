package com.example.ai_resume_builder.JWT;

import java.security.Key;
import java.util.Date;
import java.util.UUID;

import com.example.ai_resume_builder.model.User;
import com.example.ai_resume_builder.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;



import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${custom.app.jwtSecret}")
    private String jwtSecret;

    @Value("${custom.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${custom.app.jwtRefreshExpirationMs}")
    private int jwtRefreshExpirationMs;

    @Autowired
    private UserRepository userRepository;

    public String generateJwtToken(Authentication authentication) {
        User userPrincipal = (User) authentication.getPrincipal();
        String sub = userPrincipal.getSub();
        if (sub == null) {
            // Generate a new unique identifier for the sub claim
            sub = UUID.randomUUID().toString();
            userPrincipal.setSub(sub);
            // Save the user entity with the new sub value
            userRepository.save(userPrincipal);
            logger.info("AuthService: Generating token for sub: {}", sub);
            logger.info("AuthService: Using jwtSecret: {}", jwtSecret);
        }
        return generateTokenFromSub(sub, jwtExpirationMs);
    }

    public String generateTokenFromSub(String sub, int expirationTime) {
        return Jwts.builder()
                .setSubject(sub)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + expirationTime))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(Authentication authentication) {
        User userPrincipal = (User) authentication.getPrincipal();
        return generateTokenFromUsername(userPrincipal.getUsername(), jwtRefreshExpirationMs);
    }

    public String generateTokenFromUsername(String username, int expirationTime) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + expirationTime))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key()).build()
                .parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}
