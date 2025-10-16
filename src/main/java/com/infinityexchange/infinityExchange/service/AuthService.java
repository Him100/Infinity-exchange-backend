package com.infinityexchange.infinityExchange.service;

import com.infinityexchange.infinityExchange.dto.AuthResponse;
import com.infinityexchange.infinityExchange.dto.ChangePasswordRequest;
import com.infinityexchange.infinityExchange.dto.LoginRequest;
import com.infinityexchange.infinityExchange.dto.OtpRequest;
import com.infinityexchange.infinityExchange.entity.User;
import com.infinityexchange.infinityExchange.entity.UserRole;
import com.infinityexchange.infinityExchange.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;

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

        // // Debug logging for troubleshooting
        // System.out.println("=== CREDENTIALS VERIFICATION DEBUG ===");
        // System.out.println("Input userId: '" + userId + "'");
        // System.out.println("Found user: " + user.getUsername() + " (ID: " + user.getId() + ")");
        // System.out.println("User role: " + user.getRole());
        // System.out.println("User email: " + user.getEmail());
        // System.out.println("User active: " + user.getIsActive());
        // System.out.println("Stored OTP: '" + user.getOtp() + "'");
        // System.out.println("Input password: " + password);
        // System.out.println("Stored password: " + user.getPassword());
        // System.out.println("Passwords match: " + password.equals(user.getPassword()));
        // System.out.println("=====================================");

        if (!password.equals(user.getPassword())) {
            System.out.println("DEBUG: Password verification failed");
            return AuthResponse.builder()
                    .error("Invalid credentials")
                    .build();
        }

        // Check if user is active
        if (!user.getIsActive()) {
            System.out.println("DEBUG: User account is disabled");
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

        // // Debug logging for OTP verification
        // System.out.println("=== OTP VERIFICATION DEBUG ===");
        // System.out.println("Input userId: '" + userId + "'");
        // System.out.println("Found user: " + user.getUsername() + " (ID: " + user.getId() + ")");
        // System.out.println("User role: " + user.getRole());
        // System.out.println("Stored OTP: '" + user.getOtp() + "'");
        // System.out.println("Input OTP: '" + otp + "'");
        // System.out.println("OTP is null: " + (user.getOtp() == null));
        // System.out.println("OTP is empty: " + (user.getOtp() != null && user.getOtp().isEmpty()));
        // System.out.println("OTP length: " + (user.getOtp() != null ? user.getOtp().length() : "N/A"));
        // System.out.println("==============================");

        // Check if user has OTP in database
        if (user.getOtp() == null || user.getOtp().isEmpty()) {
            System.out.println("DEBUG: No OTP found in database - returning error");
            return AuthResponse.builder()
                    .error("No OTP found. Please contact administrator.")
                    .build();
        }

        // Verify OTP matches
        if (user.getOtp().equals(otp)) {
            System.out.println("DEBUG: OTP matches - login successful");
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

        System.out.println("DEBUG: OTP does not match - returning invalid OTP error");
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

            System.out.println("DEBUG: Password updated successfully for user: " + username);
        } catch (Exception e) {
            System.out.println("DEBUG: Error saving user to database: " + e.getMessage());
            e.printStackTrace();
            return AuthResponse.builder()
                    .error("Failed to update password in database: " + e.getMessage())
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
}