package com.infinityexchange.infinityExchange.service;

import com.infinityexchange.infinityExchange.repository.TokenBlacklistRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Date;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtService {

    @Value("${jwt.secret:mySecretKeyThatIsAtLeast32CharactersLongForHS256Algorithm}")
    private String secret;

    @Value("${jwt.expiration:86400000}")
    private Long expiration;

    private final TokenBlacklistRepository tokenBlacklistRepository;

    public String generateToken(String username, Long userId, String role, String email) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

        return Jwts.builder()
                .subject(username)
                .claim("userId", userId)
                .claim("role", role)
                .claim("email", email)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(key)
                .compact();
    }

    public Claims validateToken(String token) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractUsername(String token) {
        try {
            Claims claims = validateToken(token);
            return claims.getSubject();
        } catch (Exception e) {
            log.debug("Failed to extract username from token: {}", e.getMessage());
            return null;
        }
    }

    public boolean isTokenValid(String token) {
        try {
            Claims claims = validateToken(token);
            log.debug("Validating token claims: subject={}, expiration={}", 
                     claims.getSubject(), claims.getExpiration());

            // Check if token is expired
            if (claims.getExpiration().before(new Date())) {
                log.warn("Token expired for user: {}", claims.getSubject());
                return false;
            }

            // Check if token hash is blacklisted (hash the token before checking)
            String tokenHash = hashToken(token);
            if (tokenBlacklistRepository.isTokenBlacklisted(tokenHash, LocalDateTime.now())) {
                log.warn("Token blacklisted for user: {}", claims.getSubject());
                return false;
            }

            log.debug("Token is valid for user: {}", claims.getSubject());
            return true;
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            log.warn("Token validation failed - token expired: {}", e.getMessage());
            return false;
        } catch (io.jsonwebtoken.security.SignatureException e) {
            log.warn("Token validation failed - signature error: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage(), e);
            return false;
        }
    }

    public Long extractUserId(String token) {
        try {
            Claims claims = validateToken(token);
            return claims.get("userId", Long.class);
        } catch (Exception e) {
            log.error("Failed to extract user ID from token: {}", e.getMessage());
            return null;
        }
    }

    public String extractUserRole(String token) {
        try {
            Claims claims = validateToken(token);
            return claims.get("role", String.class);
        } catch (Exception e) {
            log.error("Failed to extract user role from token: {}", e.getMessage());
            return null;
        }
    }

    public String extractUserEmail(String token) {
        try {
            Claims claims = validateToken(token);
            return claims.get("email", String.class);
        } catch (Exception e) {
            log.error("Failed to extract user email from token: {}", e.getMessage());
            return null;
        }
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();

            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}