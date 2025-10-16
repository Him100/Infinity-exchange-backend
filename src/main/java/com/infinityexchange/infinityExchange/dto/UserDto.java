package com.infinityexchange.infinityExchange.dto;

import com.infinityexchange.infinityExchange.entity.UserRole;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDto {
    private Long id;
    private String username;
    private String email;
    private UserRole role;
    private boolean isActive;
    private boolean isVerified;
    private LocalDateTime createdAt;
}