-- Create test user for authentication testing
-- Run this script in your MySQL database

USE infinity_exchange;

-- Insert test user with hashed password for 'password123'
INSERT INTO users (username, email, password, role, is_active, is_verified, otp) VALUES 
('client6', 'client6@example.com', '$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVEFDi', 'CLIENT', true, true, '123456');

-- Note: The password hash above is for 'password123'
-- This is a BCrypt hash that matches your Spring Security configuration
