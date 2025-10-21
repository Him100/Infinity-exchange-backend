package com.infinityexchange.infinityExchange.controller;

import com.infinityexchange.infinityExchange.dto.AuthResponse;
import com.infinityexchange.infinityExchange.dto.ChangePasswordRequest;
import com.infinityexchange.infinityExchange.dto.LoginRequest;
import com.infinityexchange.infinityExchange.dto.OtpRequest;
import com.infinityexchange.infinityExchange.service.AuthService;
import com.infinityexchange.infinityExchange.service.JwtService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(
    origins = {"http://localhost:5173", "http://localhost:3000", "http://localhost:4173", "http://localhost:8080", "http://localhost:8085", "http://192.168.43.33:8080", "http://127.0.0.1:5173", "http://127.0.0.1:3000"},
    allowCredentials = "true"
)
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;

    @PostMapping("/verify-credentials")
    public ResponseEntity<AuthResponse> verifyCredentials(@RequestBody LoginRequest request) {
        AuthResponse response = authService.verifyCredentials(request);
        if (response.getError() != null) {
            return ResponseEntity.badRequest().body(response);
        }
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<AuthResponse> verifyOtp(@RequestBody OtpRequest request) {
        AuthResponse response = authService.verifyOtp(request);
        if (response.getError() != null) {
            return ResponseEntity.badRequest().body(response);
        }
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<AuthResponse> resendOtp(@RequestBody LoginRequest request) {
        AuthResponse response = authService.resendOtp(request);
        if (response.getError() != null) {
            return ResponseEntity.badRequest().body(response);
        }
        return ResponseEntity.ok(response);
    }

    @PostMapping("/change-password")
    public ResponseEntity<AuthResponse> changePassword(@Valid @RequestBody ChangePasswordRequest request) {
        // Extract the logged-in user's username from JWT token
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        System.out.println("DEBUG: Authentication object: " + authentication);
        System.out.println("DEBUG: Authentication class: " + (authentication != null ? authentication.getClass().getSimpleName() : "null"));

        if (authentication == null) {
            System.out.println("DEBUG: No authentication found in SecurityContext");
            return ResponseEntity.badRequest().body(
                AuthResponse.builder()
                    .error("User not authenticated")
                    .build()
            );
        }

        // Check if it's a valid authenticated user
        if (!authentication.isAuthenticated() || authentication.getName() == null) {
            System.out.println("DEBUG: Authentication not valid or username is null");
            return ResponseEntity.badRequest().body(
                AuthResponse.builder()
                    .error("User not authenticated")
                    .build()
            );
        }

        String username = authentication.getName();
        System.out.println("DEBUG: Extracted username from JWT: '" + username + "'");
        System.out.println("DEBUG: Authentication principal: " + authentication.getPrincipal());
        System.out.println("DEBUG: Authentication name: " + authentication.getName());

        if (username == null || username.trim().isEmpty()) {
            System.out.println("DEBUG: Username is null or empty");
            return ResponseEntity.badRequest().body(
                AuthResponse.builder()
                    .error("Invalid authentication token")
                    .build()
            );
        }

        AuthResponse response = authService.changePassword(request, username);
        if (response.getError() != null) {
            return ResponseEntity.badRequest().body(response);
        }
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<AuthResponse> logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body(
                AuthResponse.builder()
                    .error("Invalid or missing Authorization header")
                    .build()
            );
        }

        String token = authHeader.substring(7); // Remove "Bearer " prefix

        // AuthService.logout() handles invalid tokens gracefully
        // No need to validate token here since logout should work even for expired tokens
        AuthResponse response = authService.logout(token);
        if (response.getError() != null) {
            return ResponseEntity.badRequest().body(response);
        }
        return ResponseEntity.ok(response);
    }

}