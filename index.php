<?php
// ============================================
// LUXURY SAAS AUTHENTICATION SYSTEM
// ============================================
// Version: 1.0
// Author: Professional PHP Developer
// Description: Complete authentication system with signup, login,
//              email verification, password reset, and premium UI

// ============================================
// CONFIGURATION & SETUP INSTRUCTIONS
// ============================================

/**
 * SETUP INSTRUCTIONS:
 * 1. Create a MySQL/MariaDB database
 * 2. Run the SQL schema from the comment below
 * 3. Update the configuration constants below
 * 4. Upload this file to your web server
 * 5. Access via browser: https://yourdomain.com/auth.php
 *
 * For production:
 * - Move credentials to environment variables
 * - Use proper SMTP service (not mail())
 * - Implement proper logging
 * - Use HTTPS only
 */

// Database Configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'auth_system');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_CHARSET', 'utf8mb4');

// Application Configuration
define('BASE_URL', 'http://localhost/auth.php');
define('APP_NAME', 'LuxurySaaS');
define('SUPPORT_EMAIL', 'support@luxurysaas.com');

// Security Configuration
define('CSRF_TOKEN_EXPIRY', 3600); // 1 hour
define('SESSION_TIMEOUT', 1800); // 30 minutes
define('VERIFICATION_TOKEN_EXPIRY', 86400); // 24 hours
define('RESET_TOKEN_EXPIRY', 3600); // 1 hour
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_LOCKOUT_DURATION', 900); // 15 minutes

// Email Configuration (using PHP mail() for demo)
// For production, use SMTP with PHPMailer
define('MAIL_FROM', 'noreply@luxurysaas.com');
define('MAIL_FROM_NAME', APP_NAME);

// Development Mode (set to false in production)
define('DEV_MODE', true);

// ============================================
// DATABASE SCHEMA (SQL to run separately)
// ============================================
/*
CREATE DATABASE IF NOT EXISTS auth_system 
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE auth_system;

CREATE TABLE `users` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `email` VARCHAR(255) NOT NULL UNIQUE,
  `password` VARCHAR(255) NOT NULL,
  `email_verified` TINYINT(1) DEFAULT 0,
  `verification_token` VARCHAR(255) NULL,
  `verification_token_expires` DATETIME NULL,
  `reset_token` VARCHAR(255) NULL,
  `reset_token_expires` DATETIME NULL,
  `failed_login_attempts` INT DEFAULT 0,
  `last_failed_login` DATETIME NULL,
  `account_locked_until` DATETIME NULL,
  `last_login` DATETIME NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_email` (`email`),
  INDEX `idx_verification_token` (`verification_token`),
  INDEX `idx_reset_token` (`reset_token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
*/

// ============================================
// DATABASE CONNECTION
// ============================================

/**
 * Establish PDO database connection
 * 
 * @return PDO Database connection instance
 * @throws PDOException If connection fails
 */
function getDBConnection() {
    static $pdo = null;
    
    if ($pdo === null) {
        try {
            $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES " . DB_CHARSET
            ];
            
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            throw new Exception("Database connection error. Please try again later.");
        }
    }
    
    return $pdo;
}

// ============================================
// SESSION MANAGEMENT
// ============================================

/**
 * Initialize secure session settings
 */
function initSession() {
    if (session_status() === PHP_SESSION_NONE) {
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'domain' => '',
            'secure' => true, // Set to true in production
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
        
        session_name('luxury_saas_auth');
        session_start();
        
        // Regenerate session ID periodically for security
        if (!isset($_SESSION['last_regeneration'])) {
            session_regenerate_id(true);
            $_SESSION['last_regeneration'] = time();
        } elseif (time() - $_SESSION['last_regeneration'] > 300) {
            session_regenerate_id(true);
            $_SESSION['last_regeneration'] = time();
        }
    }
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

/**
 * Generate cryptographically secure token
 * 
 * @param int $length Token length in bytes
 * @return string Hexadecimal token
 */
function generateToken($length = 32) {
    return bin2hex(random_bytes($length));
}

/**
 * Generate and store CSRF token
 * 
 * @return string CSRF token
 */
function generateCSRFToken() {
    if (empty($_SESSION['csrf_token']) || 
        (isset($_SESSION['csrf_token_expiry']) && 
         time() > $_SESSION['csrf_token_expiry'])) {
        
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_expiry'] = time() + CSRF_TOKEN_EXPIRY;
    }
    
    return $_SESSION['csrf_token'];
}

/**
 * Validate CSRF token
 * 
 * @param string $token Token from form
 * @return bool True if valid
 */
function validateCSRFToken($token) {
    if (empty($_SESSION['csrf_token']) || 
        empty($token) || 
        !hash_equals($_SESSION['csrf_token'], $token)) {
        return false;
    }
    
    // Clear used token
    unset($_SESSION['csrf_token'], $_SESSION['csrf_token_expiry']);
    return true;
}

/**
 * Sanitize user input
 * 
 * @param mixed $data Input data
 * @return mixed Sanitized data
 */
function sanitizeInput($data) {
    if (is_array($data)) {
        return array_map('sanitizeInput', $data);
    }
    
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    
    return $data;
}

/**
 * Escape output for HTML
 * 
 * @param string $string String to escape
 * @return string Escaped string
 */
function escapeOutput($string) {
    return htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
}

/**
 * Validate email format
 * 
 * @param string $email Email address
 * @return bool True if valid
 */
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Validate password strength
 * 
 * @param string $password Password
 * @return array ['valid' => bool, 'errors' => array]
 */
function validatePassword($password) {
    $errors = [];
    
    if (strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters";
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "Password must contain at least one uppercase letter";
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "Password must contain at least one lowercase letter";
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "Password must contain at least one number";
    }
    
    if (!preg_match('/[\W_]/', $password)) {
        $errors[] = "Password must contain at least one special character";
    }
    
    return [
        'valid' => empty($errors),
        'errors' => $errors
    ];
}

/**
 * Check if rate limit is exceeded
 * 
 * @param string $email User email
 * @param PDO $pdo Database connection
 * @return array ['locked' => bool, 'until' => datetime|null]
 */
function checkRateLimit($email, $pdo) {
    try {
        $stmt = $pdo->prepare("
            SELECT failed_login_attempts, account_locked_until 
            FROM users 
            WHERE email = ?
        ");
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        
        if (!$user) {
            return ['locked' => false, 'until' => null];
        }
        
        if ($user['account_locked_until'] && 
            strtotime($user['account_locked_until']) > time()) {
            return [
                'locked' => true,
                'until' => $user['account_locked_until']
            ];
        }
        
        // Reset lock if expired
        if ($user['account_locked_until'] && 
            strtotime($user['account_locked_until']) <= time()) {
            $stmt = $pdo->prepare("
                UPDATE users 
                SET failed_login_attempts = 0, 
                    account_locked_until = NULL 
                WHERE email = ?
            ");
            $stmt->execute([$email]);
        }
        
        return [
            'locked' => false,
            'until' => $user['account_locked_until']
        ];
    } catch (PDOException $e) {
        error_log("Rate limit check failed: " . $e->getMessage());
        return ['locked' => false, 'until' => null];
    }
}

// ============================================
// AUTHENTICATION FUNCTIONS
// ============================================

/**
 * Register new user
 * 
 * @param string $email User email
 * @param string $password User password
 * @return array ['success' => bool, 'message' => string, 'user_id' => int|null]
 */
function registerUser($email, $password) {
    $pdo = getDBConnection();
    
    try {
        // Check if user already exists
        $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$email]);
        
        if ($stmt->fetch()) {
            return [
                'success' => false,
                'message' => 'This email is already registered.',
                'user_id' => null
            ];
        }
        
        // Generate verification token
        $token = generateToken();
        $tokenHash = hash('sha256', $token);
        $tokenExpiry = date('Y-m-d H:i:s', time() + VERIFICATION_TOKEN_EXPIRY);
        
        // Hash password
        $passwordHash = password_hash($password, PASSWORD_ARGON2ID);
        
        // Insert user
        $stmt = $pdo->prepare("
            INSERT INTO users (email, password, verification_token, verification_token_expires)
            VALUES (?, ?, ?, ?)
        ");
        
        $stmt->execute([
            $email,
            $passwordHash,
            $tokenHash,
            $tokenExpiry
        ]);
        
        $userId = $pdo->lastInsertId();
        
        // Send verification email
        $emailSent = sendVerificationEmail($email, $token);
        
        if (!$emailSent && !DEV_MODE) {
            // Rollback if email fails and not in dev mode
            $pdo->prepare("DELETE FROM users WHERE id = ?")->execute([$userId]);
            return [
                'success' => false,
                'message' => 'Failed to send verification email. Please try again.',
                'user_id' => null
            ];
        }
        
        return [
            'success' => true,
            'message' => 'Registration successful! Please check your email to verify your account.',
            'user_id' => $userId
        ];
        
    } catch (PDOException $e) {
        error_log("Registration failed: " . $e->getMessage());
        return [
            'success' => false,
            'message' => 'Registration failed due to a system error. Please try again.',
            'user_id' => null
        ];
    }
}

/**
 * Authenticate user login
 * 
 * @param string $email User email
 * @param string $password User password
 * @return array ['success' => bool, 'message' => string, 'user' => array|null]
 */
function authenticateUser($email, $password) {
    $pdo = getDBConnection();
    
    try {
        // Check rate limit
        $rateLimit = checkRateLimit($email, $pdo);
        if ($rateLimit['locked']) {
            return [
                'success' => false,
                'message' => 'Account is locked due to too many failed attempts. Please try again later.',
                'user' => null
            ];
        }
        
        // Get user
        $stmt = $pdo->prepare("
            SELECT id, email, password, email_verified, failed_login_attempts
            FROM users 
            WHERE email = ?
        ");
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        
        // Generic error message for security
        $errorMessage = "Invalid email or password.";
        
        if (!$user) {
            return [
                'success' => false,
                'message' => $errorMessage,
                'user' => null
            ];
        }
        
        // Check if email is verified
        if (!$user['email_verified']) {
            return [
                'success' => false,
                'message' => 'Please verify your email before logging in.',
                'user' => null
            ];
        }
        
        // Verify password
        if (!password_verify($password, $user['password'])) {
            // Increment failed attempts
            $failedAttempts = $user['failed_login_attempts'] + 1;
            
            if ($failedAttempts >= MAX_LOGIN_ATTEMPTS) {
                $lockUntil = date('Y-m-d H:i:s', time() + LOGIN_LOCKOUT_DURATION);
                $stmt = $pdo->prepare("
                    UPDATE users 
                    SET failed_login_attempts = ?, 
                        last_failed_login = NOW(),
                        account_locked_until = ?
                    WHERE email = ?
                ");
                $stmt->execute([$failedAttempts, $lockUntil, $email]);
                
                return [
                    'success' => false,
                    'message' => 'Too many failed attempts. Account locked for 15 minutes.',
                    'user' => null
                ];
            } else {
                $stmt = $pdo->prepare("
                    UPDATE users 
                    SET failed_login_attempts = ?, 
                        last_failed_login = NOW()
                    WHERE email = ?
                ");
                $stmt->execute([$failedAttempts, $email]);
                
                $remaining = MAX_LOGIN_ATTEMPTS - $failedAttempts;
                return [
                    'success' => false,
                    'message' => "$errorMessage ($remaining attempts remaining)",
                    'user' => null
                ];
            }
        }
        
        // Successful login
        // Reset failed attempts
        $stmt = $pdo->prepare("
            UPDATE users 
            SET failed_login_attempts = 0, 
                account_locked_until = NULL,
                last_login = NOW()
            WHERE email = ?
        ");
        $stmt->execute([$email]);
        
        // Get updated user data
        $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        
        return [
            'success' => true,
            'message' => 'Login successful!',
            'user' => $user
        ];
        
    } catch (PDOException $e) {
        error_log("Authentication failed: " . $e->getMessage());
        return [
            'success' => false,
            'message' => 'Authentication failed due to a system error.',
            'user' => null
        ];
    }
}

/**
 * Verify email with token
 * 
 * @param string $token Verification token
 * @return array ['success' => bool, 'message' => string]
 */
function verifyEmail($token) {
    $pdo = getDBConnection();
    
    try {
        $tokenHash = hash('sha256', $token);
        
        $stmt = $pdo->prepare("
            SELECT id, email_verified, verification_token_expires
            FROM users 
            WHERE verification_token = ?
        ");
        $stmt->execute([$tokenHash]);
        $user = $stmt->fetch();
        
        if (!$user) {
            return [
                'success' => false,
                'message' => 'Invalid verification token.'
            ];
        }
        
        if ($user['email_verified']) {
            return [
                'success' => true,
                'message' => 'Email already verified. You can log in now.'
            ];
        }
        
        // Check token expiration
        if (strtotime($user['verification_token_expires']) < time()) {
            return [
                'success' => false,
                'message' => 'Verification token has expired. Please request a new one.'
            ];
        }
        
        // Mark as verified and clear token
        $stmt = $pdo->prepare("
            UPDATE users 
            SET email_verified = 1, 
                verification_token = NULL,
                verification_token_expires = NULL
            WHERE id = ?
        ");
        $stmt->execute([$user['id']]);
        
        return [
            'success' => true,
            'message' => 'Email verified successfully! You can now log in.'
        ];
        
    } catch (PDOException $e) {
        error_log("Email verification failed: " . $e->getMessage());
        return [
            'success' => false,
            'message' => 'Verification failed due to a system error.'
        ];
    }
}

/**
 * Request password reset
 * 
 * @param string $email User email
 * @return array ['success' => bool, 'message' => string]
 */
function requestPasswordReset($email) {
    $pdo = getDBConnection();
    
    try {
        $stmt = $pdo->prepare("SELECT id, email_verified FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        
        // Always return success to prevent email enumeration
        if (!$user) {
            return [
                'success' => true,
                'message' => 'If an account exists with this email, you will receive a reset link shortly.'
            ];
        }
        
        if (!$user['email_verified']) {
            return [
                'success' => false,
                'message' => 'Please verify your email before resetting password.'
            ];
        }
        
        // Generate reset token
        $token = generateToken();
        $tokenHash = hash('sha256', $token);
        $tokenExpiry = date('Y-m-d H:i:s', time() + RESET_TOKEN_EXPIRY);
        
        // Store token
        $stmt = $pdo->prepare("
            UPDATE users 
            SET reset_token = ?, 
                reset_token_expires = ?
            WHERE id = ?
        ");
        $stmt->execute([$tokenHash, $tokenExpiry, $user['id']]);
        
        // Send reset email
        $emailSent = sendPasswordResetEmail($email, $token);
        
        return [
            'success' => true,
            'message' => 'If an account exists with this email, you will receive a reset link shortly.'
        ];
        
    } catch (PDOException $e) {
        error_log("Password reset request failed: " . $e->getMessage());
        return [
            'success' => false,
            'message' => 'Failed to process reset request. Please try again.'
        ];
    }
}

/**
 * Reset password with token
 * 
 * @param string $token Reset token
 * @param string $password New password
 * @return array ['success' => bool, 'message' => string]
 */
function resetPassword($token, $password) {
    $pdo = getDBConnection();
    
    try {
        $tokenHash = hash('sha256', $token);
        
        $stmt = $pdo->prepare("
            SELECT id, reset_token_expires
            FROM users 
            WHERE reset_token = ?
        ");
        $stmt->execute([$tokenHash]);
        $user = $stmt->fetch();
        
        if (!$user) {
            return [
                'success' => false,
                'message' => 'Invalid reset token.'
            ];
        }
        
        // Check token expiration
        if (strtotime($user['reset_token_expires']) < time()) {
            return [
                'success' => false,
                'message' => 'Reset token has expired. Please request a new one.'
            ];
        }
        
        // Validate password
        $passwordValidation = validatePassword($password);
        if (!$passwordValidation['valid']) {
            return [
                'success' => false,
                'message' => implode(' ', $passwordValidation['errors'])
            ];
        }
        
        // Hash new password
        $passwordHash = password_hash($password, PASSWORD_ARGON2ID);
        
        // Update password and clear reset token
        $stmt = $pdo->prepare("
            UPDATE users 
            SET password = ?, 
                reset_token = NULL,
                reset_token_expires = NULL,
                failed_login_attempts = 0,
                account_locked_until = NULL
            WHERE id = ?
        ");
        $stmt->execute([$passwordHash, $user['id']]);
        
        return [
            'success' => true,
            'message' => 'Password reset successful! You can now log in with your new password.'
        ];
        
    } catch (PDOException $e) {
        error_log("Password reset failed: " . $e->getMessage());
        return [
            'success' => false,
            'message' => 'Failed to reset password. Please try again.'
        ];
    }
}

/**
 * Check if user is authenticated
 * 
 * @return bool True if authenticated
 */
function isAuthenticated() {
    return isset($_SESSION['user_id'], $_SESSION['authenticated']) && 
           $_SESSION['authenticated'] === true;
}

/**
 * Get current user data
 * 
 * @return array|null User data or null
 */
function getCurrentUser() {
    if (!isAuthenticated()) {
        return null;
    }
    
    try {
        $pdo = getDBConnection();
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        return $stmt->fetch();
    } catch (PDOException $e) {
        error_log("Get user failed: " . $e->getMessage());
        return null;
    }
}

// ============================================
// EMAIL FUNCTIONS
// ============================================

/**
 * Send verification email
 * 
 * @param string $email Recipient email
 * @param string $token Verification token
 * @return bool True if sent successfully
 */
function sendVerificationEmail($email, $token) {
    $verificationUrl = BASE_URL . '?action=verify&token=' . $token;
    
    $subject = 'Verify Your Email - ' . APP_NAME;
    
    $message = '
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verify Your Email</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { text-align: center; padding: 30px 0; }
            .logo { color: #0066FF; font-size: 28px; font-weight: bold; }
            .content { background: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.07); }
            .button { display: inline-block; padding: 14px 28px; background: linear-gradient(135deg, #0066FF, #0052CC); color: white; text-decoration: none; border-radius: 8px; font-weight: 600; }
            .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">' . APP_NAME . '</div>
            </div>
            <div class="content">
                <h2>Welcome to ' . APP_NAME . '!</h2>
                <p>Thank you for registering. Please verify your email address by clicking the button below:</p>
                <p style="text-align: center; margin: 40px 0;">
                    <a href="' . $verificationUrl . '" class="button">Verify Email Address</a>
                </p>
                <p>Or copy and paste this link in your browser:</p>
                <p><code>' . $verificationUrl . '</code></p>
                <p>This link will expire in 24 hours.</p>
                <p>If you didn\'t create an account with us, please ignore this email.</p>
            </div>
            <div class="footer">
                <p>&copy; ' . date('Y') . ' ' . APP_NAME . '. All rights reserved.</p>
                <p>This is an automated message, please do not reply to this email.</p>
            </div>
        </div>
    </body>
    </html>
    ';
    
    // For demo purposes, using mail()
    // In production, use PHPMailer or similar with SMTP
    $headers = [
        'MIME-Version: 1.0',
        'Content-type: text/html; charset=UTF-8',
        'From: ' . MAIL_FROM_NAME . ' <' . MAIL_FROM . '>',
        'Reply-To: ' . SUPPORT_EMAIL,
        'X-Mailer: PHP/' . phpversion()
    ];
    
    if (DEV_MODE) {
        // In dev mode, just log the email
        error_log("Verification email to $email: $verificationUrl");
        return true;
    }
    
    return mail($email, $subject, $message, implode("\r\n", $headers));
}

/**
 * Send password reset email
 * 
 * @param string $email Recipient email
 * @param string $token Reset token
 * @return bool True if sent successfully
 */
function sendPasswordResetEmail($email, $token) {
    $resetUrl = BASE_URL . '?action=reset&token=' . $token;
    
    $subject = 'Reset Your Password - ' . APP_NAME;
    
    $message = '
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reset Your Password</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { text-align: center; padding: 30px 0; }
            .logo { color: #0066FF; font-size: 28px; font-weight: bold; }
            .content { background: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.07); }
            .button { display: inline-block; padding: 14px 28px; background: linear-gradient(135deg, #0066FF, #0052CC); color: white; text-decoration: none; border-radius: 8px; font-weight: 600; }
            .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
            .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 6px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">' . APP_NAME . '</div>
            </div>
            <div class="content">
                <h2>Password Reset Request</h2>
                <p>We received a request to reset your password. Click the button below to create a new password:</p>
                <p style="text-align: center; margin: 40px 0;">
                    <a href="' . $resetUrl . '" class="button">Reset Password</a>
                </p>
                <p>Or copy and paste this link in your browser:</p>
                <p><code>' . $resetUrl . '</code></p>
                <div class="warning">
                    <strong>Important:</strong> This link will expire in 1 hour. If you didn\'t request a password reset, please ignore this email or contact support if you\'re concerned.
                </div>
                <p>For security reasons, we recommend choosing a strong password that you haven\'t used before.</p>
            </div>
            <div class="footer">
                <p>&copy; ' . date('Y') . ' ' . APP_NAME . '. All rights reserved.</p>
                <p>This is an automated message, please do not reply to this email.</p>
            </div>
        </div>
    </body>
    </html>
    ';
    
    // For demo purposes, using mail()
    $headers = [
        'MIME-Version: 1.0',
        'Content-type: text/html; charset=UTF-8',
        'From: ' . MAIL_FROM_NAME . ' <' . MAIL_FROM . '>',
        'Reply-To: ' . SUPPORT_EMAIL,
        'X-Mailer: PHP/' . phpversion()
    ];
    
    if (DEV_MODE) {
        // In dev mode, just log the email
        error_log("Reset email to $email: $resetUrl");
        return true;
    }
    
    return mail($email, $subject, $message, implode("\r\n", $headers));
}

// ============================================
// ROUTING & CONTROLLER LOGIC
// ============================================

// Initialize session
initSession();

// Handle actions
$action = $_GET['action'] ?? 'login';
$action = in_array($action, ['login', 'signup', 'verify', 'forgot', 'reset', 'dashboard', 'logout']) 
          ? $action : 'login';

// Handle POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = array_map('sanitizeInput', $_POST);
    
    // Validate CSRF token
    if (!validateCSRFToken($data['csrf_token'] ?? '')) {
        $error = 'Security token invalid or expired. Please try again.';
    } else {
        switch ($action) {
            case 'signup':
                $email = $data['email'] ?? '';
                $password = $data['password'] ?? '';
                $confirm_password = $data['confirm_password'] ?? '';
                
                if (!validateEmail($email)) {
                    $error = 'Please enter a valid email address.';
                } elseif ($password !== $confirm_password) {
                    $error = 'Passwords do not match.';
                } else {
                    $validation = validatePassword($password);
                    if (!$validation['valid']) {
                        $error = implode(' ', $validation['errors']);
                    } else {
                        $result = registerUser($email, $password);
                        if ($result['success']) {
                            $success = $result['message'];
                            $action = 'login'; // Switch to login view
                        } else {
                            $error = $result['message'];
                        }
                    }
                }
                break;
                
            case 'login':
                $email = $data['email'] ?? '';
                $password = $data['password'] ?? '';
                
                if (empty($email) || empty($password)) {
                    $error = 'Please enter both email and password.';
                } else {
                    $result = authenticateUser($email, $password);
                    if ($result['success']) {
                        // Create session
                        $_SESSION['user_id'] = $result['user']['id'];
                        $_SESSION['authenticated'] = true;
                        $_SESSION['login_time'] = time();
                        session_regenerate_id(true);
                        
                        // Redirect to dashboard
                        header('Location: ' . BASE_URL . '?action=dashboard');
                        exit;
                    } else {
                        $error = $result['message'];
                    }
                }
                break;
                
            case 'forgot':
                $email = $data['email'] ?? '';
                
                if (!validateEmail($email)) {
                    $error = 'Please enter a valid email address.';
                } else {
                    $result = requestPasswordReset($email);
                    if ($result['success']) {
                        $success = $result['message'];
                    } else {
                        $error = $result['message'];
                    }
                }
                break;
                
            case 'reset':
                $token = $_GET['token'] ?? '';
                $password = $data['password'] ?? '';
                $confirm_password = $data['confirm_password'] ?? '';
                
                if (empty($token)) {
                    $error = 'Invalid reset token.';
                } elseif ($password !== $confirm_password) {
                    $error = 'Passwords do not match.';
                } else {
                    $validation = validatePassword($password);
                    if (!$validation['valid']) {
                        $error = implode(' ', $validation['errors']);
                    } else {
                        $result = resetPassword($token, $password);
                        if ($result['success']) {
                            $success = $result['message'];
                            $action = 'login';
                        } else {
                            $error = $result['message'];
                        }
                    }
                }
                break;
        }
    }
}

// Handle GET actions
switch ($action) {
    case 'verify':
        $token = $_GET['token'] ?? '';
        if (empty($token)) {
            $error = 'No verification token provided.';
        } else {
            $result = verifyEmail($token);
            if ($result['success']) {
                $success = $result['message'];
            } else {
                $error = $result['message'];
            }
        }
        $action = 'login';
        break;
        
    case 'logout':
        // Clear all session data
        $_SESSION = [];
        
        // Delete session cookie
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        
        // Destroy session
        session_destroy();
        
        // Redirect to login
        header('Location: ' . BASE_URL . '?action=login');
        exit;
        break;
        
    case 'dashboard':
        if (!isAuthenticated()) {
            header('Location: ' . BASE_URL . '?action=login');
            exit;
        }
        break;
}

// ============================================
// HTML/CSS/JS OUTPUT
// ============================================
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo APP_NAME; ?> - Authentication</title>
    <style>
        /* CSS Custom Properties */
        :root {
            --primary: #0066FF;
            --primary-dark: #0052CC;
            --primary-light: #E6F0FF;
            --success: #10B981;
            --danger: #EF4444;
            --warning: #F59E0B;
            --text-primary: #1F2937;
            --text-secondary: #6B7280;
            --bg-light: #FAFAFA;
            --bg-dark: #0F0F0F;
            --bg-card: #FFFFFF;
            --border: #E5E7EB;
            --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.05);
            --shadow: 0 4px 6px rgba(0, 0, 0, 0.07);
            --shadow-lg: 0 10px 15px rgba(0, 0, 0, 0.1);
            --radius-sm: 6px;
            --radius: 12px;
            --radius-lg: 20px;
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        /* Base Styles */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
            background: linear-gradient(135deg, var(--bg-light) 0%, #f0f4f8 100%);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
            padding: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .container {
            width: 100%;
            max-width: 440px;
            margin: 0 auto;
        }
        
        /* Card Styles */
        .auth-card {
            background: var(--bg-card);
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-lg);
            overflow: hidden;
            transition: var(--transition);
        }
        
        .card-header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
            padding: 40px 32px;
            text-align: center;
        }
        
        .logo {
            font-size: 32px;
            font-weight: 700;
            letter-spacing: -0.5px;
            margin-bottom: 8px;
        }
        
        .tagline {
            font-size: 16px;
            opacity: 0.9;
            font-weight: 400;
        }
        
        .card-body {
            padding: 40px 32px;
        }
        
        /* Form Styles */
        .form-group {
            margin-bottom: 24px;
            position: relative;
        }
        
        .form-label {
            display: block;
            font-size: 14px;
            font-weight: 500;
            color: var(--text-primary);
            margin-bottom: 8px;
        }
        
        .form-input {
            width: 100%;
            padding: 14px 16px;
            font-size: 16px;
            border: 2px solid var(--border);
            border-radius: var(--radius);
            background: white;
            transition: var(--transition);
            outline: none;
        }
        
        .form-input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px var(--primary-light);
        }
        
        .form-input.error {
            border-color: var(--danger);
        }
        
        .form-input.success {
            border-color: var(--success);
        }
        
        .error-message {
            color: var(--danger);
            font-size: 14px;
            margin-top: 4px;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        
        .success-message {
            color: var(--success);
            font-size: 14px;
            margin-top: 4px;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        
        /* Password Strength Indicator */
        .password-strength {
            margin-top: 8px;
            height: 4px;
            background: var(--border);
            border-radius: 2px;
            overflow: hidden;
        }
        
        .strength-bar {
            height: 100%;
            width: 0;
            transition: var(--transition);
        }
        
        .strength-weak { background: var(--danger); }
        .strength-medium { background: var(--warning); }
        .strength-strong { background: var(--success); }
        
        /* Button Styles */
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 14px 24px;
            font-size: 16px;
            font-weight: 600;
            border: none;
            border-radius: var(--radius);
            cursor: pointer;
            transition: var(--transition);
            text-decoration: none;
            gap: 8px;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
            width: 100%;
        }
        
        .btn-primary:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 12px rgba(0, 102, 255, 0.2);
        }
        
        .btn-primary:active {
            transform: translateY(0);
        }
        
        .btn-secondary {
            background: transparent;
            color: var(--primary);
            padding: 10px 16px;
        }
        
        .btn-secondary:hover {
            background: var(--primary-light);
        }
        
        /* Link Styles */
        .auth-link {
            color: var(--primary);
            text-decoration: none;
            font-weight: 500;
            transition: var(--transition);
        }
        
        .auth-link:hover {
            text-decoration: underline;
        }
        
        /* Alert Styles */
        .alert {
            padding: 16px;
            border-radius: var(--radius);
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .alert-error {
            background: #FEF2F2;
            border: 1px solid #FECACA;
            color: var(--danger);
        }
        
        .alert-success {
            background: #ECFDF5;
            border: 1px solid #A7F3D0;
            color: var(--success);
        }
        
        /* Dashboard Styles */
        .dashboard-header {
            padding: 32px;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
        }
        
        .dashboard-content {
            padding: 32px;
        }
        
        .user-info {
            background: var(--bg-card);
            border-radius: var(--radius);
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: var(--shadow);
        }
        
        .info-item {
            display: flex;
            justify-content: space-between;
            padding: 12px 0;
            border-bottom: 1px solid var(--border);
        }
        
        .info-item:last-child {
            border-bottom: none;
        }
        
        .info-label {
            color: var(--text-secondary);
            font-weight: 500;
        }
        
        .info-value {
            color: var(--text-primary);
            font-weight: 600;
        }
        
        .verified-badge {
            background: var(--success);
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 500;
        }
        
        .unverified-badge {
            background: var(--warning);
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 500;
        }
        
        /* Loading Spinner */
        .spinner {
            width: 20px;
            height: 20px;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-top-color: white;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        /* Responsive */
        @media (max-width: 480px) {
            body {
                padding: 16px;
            }
            
            .card-header,
            .card-body {
                padding: 32px 24px;
            }
            
            .dashboard-content {
                padding: 24px;
            }
        }
        
        /* Password Toggle */
        .password-toggle {
            position: absolute;
            right: 16px;
            top: 42px;
            background: none;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            padding: 4px;
            font-size: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <?php if ($action === 'dashboard'): ?>
            <!-- Dashboard View -->
            <?php $user = getCurrentUser(); ?>
            <div class="auth-card">
                <div class="dashboard-header">
                    <h1 class="logo"><?php echo APP_NAME; ?></h1>
                    <p class="tagline">Welcome back, <?php echo escapeOutput($user['email']); ?></p>
                </div>
                
                <div class="dashboard-content">
                    <?php if (isset($success)): ?>
                        <div class="alert alert-success">
                            <span>✓</span>
                            <span><?php echo escapeOutput($success); ?></span>
                        </div>
                    <?php endif; ?>
                    
                    <?php if (isset($error)): ?>
                        <div class="alert alert-error">
                            <span>✗</span>
                            <span><?php echo escapeOutput($error); ?></span>
                        </div>
                    <?php endif; ?>
                    
                    <div class="user-info">
                        <h2 style="margin-bottom: 20px; font-size: 24px;">Account Information</h2>
                        
                        <div class="info-item">
                            <span class="info-label">Email Address</span>
                            <span class="info-value"><?php echo escapeOutput($user['email']); ?></span>
                        </div>
                        
                        <div class="info-item">
                            <span class="info-label">Account Created</span>
                            <span class="info-value"><?php echo date('F j, Y', strtotime($user['created_at'])); ?></span>
                        </div>
                        
                        <div class="info-item">
                            <span class="info-label">Email Verification</span>
                            <span class="info-value">
                                <?php if ($user['email_verified']): ?>
                                    <span class="verified-badge">Verified ✓</span>
                                <?php else: ?>
                                    <span class="unverified-badge">Not Verified</span>
                                <?php endif; ?>
                            </span>
                        </div>
                        
                        <?php if ($user['last_login']): ?>
                        <div class="info-item">
                            <span class="info-label">Last Login</span>
                            <span class="info-value"><?php echo date('F j, Y \a\t g:i A', strtotime($user['last_login'])); ?></span>
                        </div>
                        <?php endif; ?>
                    </div>
                    
                    <div style="display: flex; gap: 12px; margin-top: 32px;">
                        <a href="?action=logout" class="btn btn-primary" style="flex: 1;">
                            Log Out
                        </a>
                        <a href="?action=forgot" class="btn btn-secondary" style="flex: 1;">
                            Reset Password
                        </a>
                    </div>
                </div>
            </div>
            
        <?php else: ?>
            <!-- Auth Forms -->
            <div class="auth-card">
                <div class="card-header">
                    <h1 class="logo"><?php echo APP_NAME; ?></h1>
                    <p class="tagline"><?php echo $action === 'login' ? 'Welcome back' : 'Join us today'; ?></p>
                </div>
                
                <div class="card-body">
                    <?php if (isset($success)): ?>
                        <div class="alert alert-success">
                            <span>✓</span>
                            <span><?php echo escapeOutput($success); ?></span>
                        </div>
                    <?php endif; ?>
                    
                    <?php if (isset($error)): ?>
                        <div class="alert alert-error">
                            <span>✗</span>
                            <span><?php echo escapeOutput($error); ?></span>
                        </div>
                    <?php endif; ?>
                    
                    <?php if ($action === 'signup'): ?>
                        <!-- Signup Form -->
                        <form method="POST" action="?action=signup" id="signupForm">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            
                            <div class="form-group">
                                <label class="form-label">Email Address</label>
                                <input type="email" name="email" class="form-input" required 
                                       placeholder="you@example.com" id="emailInput">
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">Password</label>
                                <div style="position: relative;">
                                    <input type="password" name="password" class="form-input" required 
                                           placeholder="••••••••" id="passwordInput"
                                           minlength="8">
                                    <button type="button" class="password-toggle" onclick="togglePassword('passwordInput')">
                                        👁
                                    </button>
                                </div>
                                <div class="password-strength">
                                    <div class="strength-bar" id="strengthBar"></div>
                                </div>
                                <div id="passwordErrors" class="error-message"></div>
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">Confirm Password</label>
                                <div style="position: relative;">
                                    <input type="password" name="confirm_password" class="form-input" required 
                                           placeholder="••••••••" id="confirmPasswordInput">
                                    <button type="button" class="password-toggle" onclick="togglePassword('confirmPasswordInput')">
                                        👁
                                    </button>
                                </div>
                                <div id="confirmError" class="error-message"></div>
                            </div>
                            
                            <button type="submit" class="btn btn-primary" id="signupBtn">
                                Create Account
                            </button>
                        </form>
                        
                        <div style="text-align: center; margin-top: 24px;">
                            <span style="color: var(--text-secondary);">Already have an account?</span>
                            <a href="?action=login" class="auth-link">Sign in</a>
                        </div>
                        
                    <?php elseif ($action === 'forgot'): ?>
                        <!-- Forgot Password Form -->
                        <form method="POST" action="?action=forgot">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            
                            <div class="form-group">
                                <label class="form-label">Email Address</label>
                                <input type="email" name="email" class="form-input" required 
                                       placeholder="you@example.com">
                            </div>
                            
                            <button type="submit" class="btn btn-primary">
                                Send Reset Link
                            </button>
                        </form>
                        
                        <div style="text-align: center; margin-top: 24px;">
                            <a href="?action=login" class="auth-link">Back to login</a>
                        </div>
                        
                    <?php elseif ($action === 'reset'): ?>
                        <!-- Reset Password Form -->
                        <?php $token = $_GET['token'] ?? ''; ?>
                        <form method="POST" action="?action=reset&token=<?php echo escapeOutput($token); ?>">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            
                            <div class="form-group">
                                <label class="form-label">New Password</label>
                                <div style="position: relative;">
                                    <input type="password" name="password" class="form-input" required 
                                           placeholder="••••••••" id="resetPasswordInput"
                                           minlength="8">
                                    <button type="button" class="password-toggle" onclick="togglePassword('resetPasswordInput')">
                                        👁
                                    </button>
                                </div>
                                <div class="password-strength">
                                    <div class="strength-bar" id="resetStrengthBar"></div>
                                </div>
                                <div id="resetPasswordErrors" class="error-message"></div>
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">Confirm New Password</label>
                                <div style="position: relative;">
                                    <input type="password" name="confirm_password" class="form-input" required 
                                           placeholder="••••••••" id="resetConfirmPasswordInput">
                                    <button type="button" class="password-toggle" onclick="togglePassword('resetConfirmPasswordInput')">
                                        👁
                                    </button>
                                </div>
                                <div id="resetConfirmError" class="error-message"></div>
                            </div>
                            
                            <button type="submit" class="btn btn-primary" id="resetBtn">
                                Reset Password
                            </button>
                        </form>
                        
                    <?php else: ?>
                        <!-- Login Form (default) -->
                        <form method="POST" action="?action=login">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            
                            <div class="form-group">
                                <label class="form-label">Email Address</label>
                                <input type="email" name="email" class="form-input" required 
                                       placeholder="you@example.com">
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">Password</label>
                                <div style="position: relative;">
                                    <input type="password" name="password" class="form-input" required 
                                           placeholder="••••••••">
                                    <button type="button" class="password-toggle" onclick="togglePassword(this.previousElementSibling)">
                                        👁
                                    </button>
                                </div>
                            </div>
                            
                            <button type="submit" class="btn btn-primary">
                                Sign In
                            </button>
                        </form>
                        
                        <div style="text-align: center; margin-top: 24px;">
                            <a href="?action=forgot" class="auth-link">Forgot password?</a>
                            <span style="color: var(--text-secondary); margin: 0 8px;">•</span>
                            <span style="color: var(--text-secondary);">Don't have an account?</span>
                            <a href="?action=signup" class="auth-link">Sign up</a>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        <?php endif; ?>
        
        <!-- Demo Notice -->
        <?php if (DEV_MODE): ?>
        <div style="text-align: center; margin-top: 24px; color: var(--text-secondary); font-size: 14px;">
            <p>Demo Mode: Emails are logged to server error log instead of being sent.</p>
            <p>For production: Set DEV_MODE to false and configure proper SMTP.</p>
        </div>
        <?php endif; ?>
    </div>

    <script>
        // Password strength indicator
        function checkPasswordStrength(password) {
            let strength = 0;
            
            if (password.length >= 8) strength++;
            if (/[A-Z]/.test(password)) strength++;
            if (/[a-z]/.test(password)) strength++;
            if (/[0-9]/.test(password)) strength++;
            if (/[\W_]/.test(password)) strength++;
            
            return strength;
        }
        
        function updateStrengthBar(inputId, barId) {
            const input = document.getElementById(inputId);
            const bar = document.getElementById(barId);
            const strength = checkPasswordStrength(input.value);
            
            bar.className = 'strength-bar';
            bar.style.width = '0%';
            
            if (input.value.length === 0) return;
            
            if (strength <= 2) {
                bar.style.width = '33%';
                bar.classList.add('strength-weak');
            } else if (strength <= 4) {
                bar.style.width = '66%';
                bar.classList.add('strength-medium');
            } else {
                bar.style.width = '100%';
                bar.classList.add('strength-strong');
            }
        }
        
        // Password validation
        function validatePasswordInput(password) {
            const errors = [];
            
            if (password.length < 8) {
                errors.push('Minimum 8 characters');
            }
            if (!/[A-Z]/.test(password)) {
                errors.push('One uppercase letter');
            }
            if (!/[a-z]/.test(password)) {
                errors.push('One lowercase letter');
            }
            if (!/[0-9]/.test(password)) {
                errors.push('One number');
            }
            if (!/[\W_]/.test(password)) {
                errors.push('One special character');
            }
            
            return errors;
        }
        
        // Toggle password visibility
        function togglePassword(inputId) {
            const input = typeof inputId === 'string' 
                ? document.getElementById(inputId)
                : inputId;
            
            const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
            input.setAttribute('type', type);
        }
        
        // Form validation for signup
        document.addEventListener('DOMContentLoaded', function() {
            const signupForm = document.getElementById('signupForm');
            if (signupForm) {
                const passwordInput = document.getElementById('passwordInput');
                const confirmInput = document.getElementById('confirmPasswordInput');
                const passwordErrors = document.getElementById('passwordErrors');
                const confirmError = document.getElementById('confirmError');
                const signupBtn = document.getElementById('signupBtn');
                
                passwordInput.addEventListener('input', function() {
                    updateStrengthBar('passwordInput', 'strengthBar');
                    
                    const errors = validatePasswordInput(this.value);
                    if (errors.length > 0) {
                        passwordErrors.textContent = 'Requirements: ' + errors.join(', ');
                        passwordErrors.style.display = 'block';
                        signupBtn.disabled = true;
                        signupBtn.style.opacity = '0.6';
                    } else {
                        passwordErrors.style.display = 'none';
                        signupBtn.disabled = false;
                        signupBtn.style.opacity = '1';
                    }
                    
                    // Check password match
                    if (confirmInput.value && this.value !== confirmInput.value) {
                        confirmError.textContent = 'Passwords do not match';
                        confirmError.style.display = 'block';
                        signupBtn.disabled = true;
                        signupBtn.style.opacity = '0.6';
                    } else {
                        confirmError.style.display = 'none';
                        if (passwordErrors.style.display === 'none') {
                            signupBtn.disabled = false;
                            signupBtn.style.opacity = '1';
                        }
                    }
                });
                
                confirmInput.addEventListener('input', function() {
                    if (passwordInput.value !== this.value) {
                        confirmError.textContent = 'Passwords do not match';
                        confirmError.style.display = 'block';
                        signupBtn.disabled = true;
                        signupBtn.style.opacity = '0.6';
                    } else {
                        confirmError.style.display = 'none';
                        if (passwordErrors.style.display === 'none') {
                            signupBtn.disabled = false;
                            signupBtn.style.opacity = '1';
                        }
                    }
                });
            }
            
            // Form validation for reset
            const resetForm = document.querySelector('form[action*="reset"]');
            if (resetForm) {
                const passwordInput = document.getElementById('resetPasswordInput');
                const confirmInput = document.getElementById('resetConfirmPasswordInput');
                const passwordErrors = document.getElementById('resetPasswordErrors');
                const confirmError = document.getElementById('resetConfirmError');
                const resetBtn = document.getElementById('resetBtn');
                
                if (passwordInput) {
                    passwordInput.addEventListener('input', function() {
                        updateStrengthBar('resetPasswordInput', 'resetStrengthBar');
                        
                        const errors = validatePasswordInput(this.value);
                        if (errors.length > 0) {
                            passwordErrors.textContent = 'Requirements: ' + errors.join(', ');
                            passwordErrors.style.display = 'block';
                            resetBtn.disabled = true;
                            resetBtn.style.opacity = '0.6';
                        } else {
                            passwordErrors.style.display = 'none';
                            resetBtn.disabled = false;
                            resetBtn.style.opacity = '1';
                        }
                        
                        // Check password match
                        if (confirmInput.value && this.value !== confirmInput.value) {
                            confirmError.textContent = 'Passwords do not match';
                            confirmError.style.display = 'block';
                            resetBtn.disabled = true;
                            resetBtn.style.opacity = '0.6';
                        } else {
                            confirmError.style.display = 'none';
                            if (passwordErrors.style.display === 'none') {
                                resetBtn.disabled = false;
                                resetBtn.style.opacity = '1';
                            }
                        }
                    });
                    
                    if (confirmInput) {
                        confirmInput.addEventListener('input', function() {
                            if (passwordInput.value !== this.value) {
                                confirmError.textContent = 'Passwords do not match';
                                confirmError.style.display = 'block';
                                resetBtn.disabled = true;
                                resetBtn.style.opacity = '0.6';
                            } else {
                                confirmError.style.display = 'none';
                                if (passwordErrors.style.display === 'none') {
                                    resetBtn.disabled = false;
                                    resetBtn.style.opacity = '1';
                                }
                            }
                        });
                    }
                }
            }
            
            // Auto-hide alerts after 5 seconds
            setTimeout(() => {
                const alerts = document.querySelectorAll('.alert');
                alerts.forEach(alert => {
                    alert.style.transition = 'opacity 0.5s';
                    alert.style.opacity = '0';
                    setTimeout(() => alert.remove(), 500);
                });
            }, 5000);
            
            // Form submission loading state
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                form.addEventListener('submit', function() {
                    const btn = this.querySelector('button[type="submit"]');
                    if (btn && !btn.disabled) {
                        btn.innerHTML = '<span class="spinner"></span> Processing...';
                        btn.disabled = true;
                    }
                });
            });
        });
    </script>
</body>
</html>