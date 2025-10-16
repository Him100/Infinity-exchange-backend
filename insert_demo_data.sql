-- Demo data for testing login functionality
-- These users have password 'password123' (plain text)

-- Clear existing data (optional - uncomment if you want to start fresh)
-- DELETE FROM users;

-- Insert demo users with known password 'password123'

INSERT INTO users (username, email, password, role, is_active, is_verified, otp) VALUES
('client6', 'client6@example.com', 'password123', 'CLIENT', true, true, '123456'),
('client5', 'client5@example.com', 'password123', 'CLIENT', true, true, '123456'),
('testuser', 'testuser@example.com', 'password123', 'CLIENT', true, true, '123456'),
('demo_admin', 'admin@demo.com', 'password123', 'ADMIN', true, true, '123456'),
('demo_master', 'master@demo.com', 'password123', 'MASTER', true, true, '123456');

-- Note: All users have password 'password123' (plain text)
-- CLIENT users will get direct login
-- ADMIN/MASTER users will require OTP verification (OTP: 123456)
