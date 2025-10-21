package com.infinityexchange.infinityExchange.service;

import com.infinityexchange.infinityExchange.repository.TokenBlacklistRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@SuppressWarnings("unused") // This service is instantiated by Spring and used by the scheduler
public class TokenCleanupService {

    private final TokenBlacklistRepository tokenBlacklistRepository;

    // Run every hour to clean up expired tokens
    // This method is called by Spring's scheduler, hence the "unused" warning is a false positive
    @Scheduled(fixedRate = 3600000) // 1 hour in milliseconds
    @Transactional
    @SuppressWarnings("unused") // Called by Spring scheduler
    public void cleanupExpiredTokens() {
        try {
            int deletedCount = tokenBlacklistRepository.deleteByExpiresAtBefore(LocalDateTime.now());
            if (deletedCount > 0) {
                System.out.println("Cleaned up " + deletedCount + " expired tokens from blacklist");
            }
        } catch (Exception e) {
            System.err.println("Error cleaning up expired tokens: " + e.getMessage());
        }
    }
}
