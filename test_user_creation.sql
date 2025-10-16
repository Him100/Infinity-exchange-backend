-- Create a test user with password 'password123'
-- This will help us test the authentication flow

INSERT INTO users (username, email, password, role, is_active, is_verified, otp) VALUES
('testuser', 'testuser@example.com', '$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVEFDi', 'CLIENT', true, true, '123456');

-- Note: The password hash above is for 'password123'
-- This matches the hash pattern we've seen in your existing users
