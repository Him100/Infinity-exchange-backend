package com.infinityexchange.infinityExchange.service;

import com.infinityexchange.infinityExchange.dto.AuthResponse;
import com.infinityexchange.infinityExchange.dto.ChangePasswordRequest;
import com.infinityexchange.infinityExchange.dto.LoginRequest;
import com.infinityexchange.infinityExchange.dto.OtpRequest;
import com.infinityexchange.infinityExchange.entity.TokenBlacklist;
import com.infinityexchange.infinityExchange.entity.User;
import com.infinityexchange.infinityExchange.entity.UserRole;
import com.infinityexchange.infinityExchange.repository.TokenBlacklistRepository;
import com.infinityexchange.infinityExchange.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final TokenBlacklistRepository tokenBlacklistRepository;

    public AuthResponse verifyCredentials(LoginRequest request) {
        String userId = request.getUserId();
        String password = request.getPassword();

        // Find user by username or email
        Optional<User> userOpt = userRepository.findByUsername(userId);
        if (userOpt.isEmpty()) {
            userOpt = userRepository.findByEmail(userId);
        }

        if (userOpt.isEmpty()) {
            return AuthResponse.builder()
                    .error("Invalid credentials")
                    .build();
        }

        User user = userOpt.get();

        if (!password.equals(user.getPassword())) {
            return AuthResponse.builder()
                    .error("Invalid credentials")
                    .build();
        }

        // Check if user is active
        if (!user.getIsActive()) {
            return AuthResponse.builder()
                    .error("Account is disabled")
                    .build();
        }

        // For clients, direct login with token
        if (user.getRole() == UserRole.CLIENT) {
            String token = jwtService.generateToken(
                user.getUsername(),
                user.getId(),
                user.getRole().name(),
                user.getEmail()
            );
            return AuthResponse.builder()
                    .token(token)
                    .user(user)
                    .message("Login successful")
                    .build();
        }

        // For other roles, always require OTP verification
        return AuthResponse.builder()
                .message("OTP verification required")
                .requiresOtp(true)
                .build();
    }

    public AuthResponse verifyOtp(OtpRequest request) {
        String userId = request.getUserId();
        String password = request.getPassword();
        String otp = request.getOtp();

        // Find user by username or email
        Optional<User> userOpt = userRepository.findByUsername(userId);
        if (userOpt.isEmpty()) {
            userOpt = userRepository.findByEmail(userId);
        }

        if (userOpt.isEmpty()) {
            return AuthResponse.builder()
                    .error("Invalid credentials")
                    .build();
        }

        User user = userOpt.get();

        if (!password.equals(user.getPassword())) {
            return AuthResponse.builder()
                    .error("Invalid credentials")
                    .build();
        }

        // Check if user has OTP in database
        if (user.getOtp() == null || user.getOtp().isEmpty()) {
            return AuthResponse.builder()
                    .error("No OTP found. Please contact administrator.")
                    .build();
        }

        // Verify OTP matches
        if (user.getOtp().equals(otp)) {
            // OTP is kept for reuse (not cleared)

            String token = jwtService.generateToken(
                user.getUsername(),
                user.getId(),
                user.getRole().name(),
                user.getEmail()
            );

            return AuthResponse.builder()
                    .token(token)
                    .user(user)
                    .message("Login successful")
                    .build();
        }

        return AuthResponse.builder()
                .error("Invalid OTP")
                .build();
    }

    public AuthResponse resendOtp(LoginRequest request) {
        // OTP reuse is allowed - no regeneration needed
        return AuthResponse.builder()
                .error("OTP reuse is enabled. Use the same OTP for login.")
                .build();
    }

    public AuthResponse changePassword(ChangePasswordRequest request, String username) {
        // Find user by username
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            return AuthResponse.builder()
                    .error("User not found")
                    .build();
        }

        User user = userOpt.get();

        // Validate current password (plain text comparison)
        if (!request.getCurrentPassword().equals(user.getPassword())) {
            return AuthResponse.builder()
                    .error("Current password is incorrect")
                    .build();
        }

        // Validate new password and confirm password match
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            return AuthResponse.builder()
                    .error("New password and confirm password do not match")
                    .build();
        }

        // Validate new password is not the same as current
        if (request.getNewPassword().equals(user.getPassword())) {
            return AuthResponse.builder()
                    .error("New password must be different from current password")
                    .build();
        }

        // Directly update password (no encoding, plain text)
        user.setPassword(request.getNewPassword());

        try {
            userRepository.save(user);
            userRepository.flush();
        } catch (Exception e) {
            return AuthResponse.builder()
                    .error("Failed to update password in database")
                    .build();
        }

        return AuthResponse.builder()
                .message("Password changed successfully")
                .build();
    }

    public User getCurrentUser(String username) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        return userOpt.orElse(null);
    }

    public AuthResponse logout(String token) {
        try {
            LocalDateTime expiresAt = null;
            Long userId = null;

            // Try to extract token information, but don't fail if token is invalid
            try {
                io.jsonwebtoken.Claims claims = jwtService.validateToken(token);
                expiresAt = claims.getExpiration().toInstant()
                        .atZone(java.time.ZoneId.systemDefault())
                        .toLocalDateTime();
                userId = jwtService.extractUserId(token);
            } catch (Exception e) {
                // If token is invalid, still allow logout but with current timestamp
                expiresAt = LocalDateTime.now().plusHours(1); // Default expiry
                userId = null; // We don't know the user ID
            }

            // Generate hash of the token (SHA-256) - much shorter than full token
            String tokenHash = hashToken(token);

            // Create blacklist entry with token hash instead of full token
            TokenBlacklist blacklistEntry = TokenBlacklist.builder()
                    .token(tokenHash) // Store hash instead of full token
                    .expiresAt(expiresAt)
                    .userId(userId)
                    .reason("User logout")
                    .build();

            tokenBlacklistRepository.save(blacklistEntry);

            return AuthResponse.builder()
                    .message("Logout successful")
                    .build();
        } catch (Exception e) {
            return AuthResponse.builder()
                    .error("Logout failed: " + e.getMessage())
                    .build();
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