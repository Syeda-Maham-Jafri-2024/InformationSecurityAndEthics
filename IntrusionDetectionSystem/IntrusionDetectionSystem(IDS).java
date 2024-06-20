import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

// Import statements for JavaMail API
import javax.mail.*;
import javax.mail.internet.*;

public class IntrusionDetectionSystem {
    private Map<String, Integer> loginAttempts;
    private Map<String, String> userPasswords;
    private Map<String, Integer> honeypotAttempts;
    private static final int MAX_LOGIN_ATTEMPTS = 3;
    private static final int HONEYPOT_TRIGGER_ATTEMPTS = 3;
    private static final double SIMILARITY_THRESHOLD = 0.7;
    private static final Logger logger = Logger.getLogger("IDSLogger");
    private Map<String, Boolean> blockedIPs; // Map to store blocked IP addresses
    private Set<String> whitelistedIPs;
    private Set<String> blacklistedIPs;
    private Map<String, String> otpSecrets; // Map to store OTP secrets for users
    private Set<String> blacklistedEmails; // Set to store blacklisted email addresses
    private boolean isSystemIntegrityIntact = true; // Flag to track system integrity
    private int maxTrafficThreshold = 1000; // Maximum allowed network traffic threshold

    public IntrusionDetectionSystem() {
        loginAttempts = new HashMap<>();
        userPasswords = new HashMap<>();
        honeypotAttempts = new HashMap<>();
        blockedIPs = new HashMap<>();
        whitelistedIPs = new HashSet<>();
        blacklistedIPs = new HashSet<>();
        otpSecrets = new HashMap<>();
        blacklistedEmails = new HashSet<>(); // Initialize the set for blacklisted email addresses

        // Add predefined IP addresses to the whitelist and blacklist
        whitelistedIPs.add("192.168.1.1");
        blacklistedIPs.add("10.0.0.1");

        // Initialize user passwords (in a real application, these would come from a secure source)
        userPasswords.put("user1", "password123");
        userPasswords.put("user2", "securePassword456");

        // Generate OTP secrets for users
        generateOTPSecrets();

        // Setup logging
        try {
            FileHandler fileHandler = new FileHandler("IDSLog.txt");
            SimpleFormatter formatter = new SimpleFormatter();
            fileHandler.setFormatter(formatter);
            logger.addHandler(fileHandler);
        } catch (Exception e) {
            e.printStackTrace();
            isSystemIntegrityIntact = false;
        }
    }

    public void login(String username, String password, String otp, String sourceIP, String destinationIP, String email) { // Modified to accept email and source/destination IP addresses
        // Validate source and destination IP addresses
        if (!isValidIPAddress(sourceIP) || !isValidIPAddress(destinationIP)) {
            logger.warning("Invalid source or destination IP address.");
            return;
        }

        // Check if source or destination IP address is blacklisted
        if (isBlacklisted(sourceIP) || isBlacklisted(destinationIP)) {
            logger.warning("Suspicious source/destination IP address detected. Packet entry locked!");
            return;
        }

        // Continue with login attempt checks...
        // Validate IP address
        if (!isValidIPAddress(sourceIP)) {
            logger.warning("Invalid IP address: " + sourceIP);
            return;
        }

        // Check if IP address is blacklisted
        if (isBlacklisted(sourceIP)) {
            logger.warning("Blocked IP address: " + sourceIP);
            return;
        }

        // Check if IP address is whitelisted
        if (!isWhitelisted(sourceIP)) {
            int attempts = loginAttempts.getOrDefault(username, 0) + 1;
            loginAttempts.put(username, attempts);

            // Log login attempt
            logger.info("Login attempt for user: " + username + " from IP: " + sourceIP);

            // Check if email is blacklisted
            if (isEmailBlacklisted(email)) {
                logger.warning("Blocked email address: " + email);
                return;
            }

            if (attempts > MAX_LOGIN_ATTEMPTS) {
                if (!isSimilarCredentials(username, password) || !verifyOTP(username, otp)) {
                    int honeypotAttempt = honeypotAttempts.getOrDefault(username, 0) + 1;
                    honeypotAttempts.put(username, honeypotAttempt);
                    if (honeypotAttempt % HONEYPOT_TRIGGER_ATTEMPTS == 0 && !isSimilarCredentialsOnHoneypot(username, password)) {
                        lockAccount(username);
                        return;
                    }
                }
            }

            // Check IP address and block if necessary
            if (attempts > MAX_LOGIN_ATTEMPTS && !blockedIPs.containsKey(sourceIP)) {
                blockIP(sourceIP);
            }
        }
    }

    // Password recovery process
    public boolean initiatePasswordRecovery(String userId) {
        // Simulate initiating the password recovery process
        // This method should send a password reset link to the user's email

        // The email address associated with the user
        String userEmail = getUserEmail(userId);
        if (userEmail != null) {
            // Generate a unique reset token (for testing purposes, we'll use a random token)
            String resetToken = generateRandomToken();

            // Send the password reset link to the user's email
            sendPasswordResetEmail(userEmail, resetToken);

            // For testing purposes, we'll assume the process always succeeds
            return true;
        }

        // Return false if the user ID is invalid or the email is not found
        return false;
    }

    public boolean resetPassword(String userId, String resetToken, String newPassword) {
        // Simulate resetting the user's password
        // This method should validate the reset token and update the user's password

        // For testing purposes, let's assume the reset token is valid
        if (validateResetToken(userId, resetToken)) {
            // Update the user's password in the database
            userPasswords.put(userId, newPassword);

            // For testing purposes, we'll assume the process always succeeds
            return true;
        }

        // Return false if the reset token is invalid
        return false;
    }

    private boolean isValidIPAddress(String ipAddress) {
        // Regular expression for IPv4 address validation
        String ipv4Pattern = "^\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b$";

        // Regular expression for IPv6 address validation
        String ipv6Pattern = "^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)$";

        return ipAddress.matches(ipv4Pattern) || ipAddress.matches(ipv6Pattern);
    }

    private boolean isWhitelisted(String ipAddress) {
        return whitelistedIPs.contains(ipAddress);
    }

    private boolean isBlacklisted(String ipAddress) {
        return blacklistedIPs.contains(ipAddress);
    }

    private boolean isSimilarCredentials(String username, String password) {
        String actualUsername = username;
        String actualPassword = userPasswords.get(username);
        return calculateSimilarity(username, actualUsername) >= SIMILARITY_THRESHOLD
                && calculateSimilarity(password, actualPassword) >= SIMILARITY_THRESHOLD;
    }

    private boolean isSimilarCredentialsOnHoneypot(String username, String password) {
        String actualUsername = username;
        String actualPassword = userPasswords.get(username);
        return calculateSimilarity(username, actualUsername) >= SIMILARITY_THRESHOLD
                && calculateSimilarity(password, actualPassword) >= SIMILARITY_THRESHOLD;
    }

    private boolean isEmailBlacklisted(String email) {
        return blacklistedEmails.contains(email);
    }

    private double calculateSimilarity(String enteredStr, String actualStr) {
        int distance = calculateLevenshteinDistance(enteredStr, actualStr);
        int maxLen = Math.max(enteredStr.length(), actualStr.length());
        return 1 - ((double) distance / maxLen);
    }

    private int calculateLevenshteinDistance(String enteredStr, String actualStr) {
        int[][] dp = new int[enteredStr.length() + 1][actualStr.length() + 1];
        for (int i = 0; i <= enteredStr.length(); i++) {
            dp[i][0] = i;
        }
        for (int j = 0; j <= actualStr.length(); j++) {
            dp[0][j] = j;
        }
        for (int i = 1; i <= enteredStr.length(); i++) {
            for (int j = 1; j <= actualStr.length(); j++) {
                if (enteredStr.charAt(i - 1) == actualStr.charAt(j - 1)) {
                    dp[i][j] = dp[i - 1][j - 1];
                } else {
                    dp[i][j] = 1 + Math.min(Math.min(dp[i][j - 1], dp[i - 1][j]), dp[i - 1][j - 1]);
                }
            }
        }
        return dp[enteredStr.length()][actualStr.length()];
    }

    private void lockAccount(String username) {
        logger.warning("Account locked for user: " + username);
    }

    private void blockIP(String ipAddress) {
        blockedIPs.put(ipAddress, true);
        logger.warning("IP address blocked: " + ipAddress);
    }

    private void generateOTPSecrets() {
        otpSecrets.put("user1", "secret123");
        otpSecrets.put("user2", "secret456");
    }

    private boolean verifyOTP(String username, String otp) {
        String secret = otpSecrets.get(username);
        return otp.equals(secret);
    }

    private void checkSystemIntegrity() {
        if (!logger.getHandlers()[0].getFormatter().getClass().equals(SimpleFormatter.class)) {
            isSystemIntegrityIntact = false;
            logger.warning("System integrity compromised: Logging system tampered with.");
        }
    }

    public void checkNetworkTraffic(int currentTraffic) {
        if (currentTraffic > maxTrafficThreshold) {
            logger.warning("Notice Alert: Network traffic is becoming too large!!");
        }
    }

    // Get the email address associated with a user ID (for testing purposes)
    private String getUserEmail(String userId) {
        // In a real system, you would retrieve the email address from a database or another source
        // For testing purposes, we'll return a hardcoded email address
        if (userId.equals("user1")) {
            return "user1@example.com";
        } else if (userId.equals("user2")) {
            return "user2@example.com";
        }
        return null; // Return null if user ID not found (for testing purposes)
    }

    // Generate a random reset token (for testing purposes)
    private String generateRandomToken() {
        // Generate a random alphanumeric string as the reset token
        // For testing purposes, we'll use a simple random string
        return "randomResetToken123";
    }

    // Validate the reset token (for testing purposes)
    private boolean validateResetToken(String userId, String resetToken) {
        // For testing purposes, let's assume the reset token is valid if it matches the expected token
        return resetToken.equals("randomResetToken123");
    }

    public static void main(String[] args) {
        IntrusionDetectionSystem ids = new IntrusionDetectionSystem();
        
        // Check system integrity before proceeding
        if(ids.isSystemIntegrityIntact) {
            // Simulate login attempts with failed credentials
            ids.login("user1", "wrongPassword1", "123456", "192.168.1.1", "10.0.0.2", "phishing@scammer.com"); // Example of using a blacklisted email and suspicious source/destination IP
            ids.login("user1", "wrongPassword2", "123456", "192.168.1.1", "192.168.1.2", "legitimate@email.com"); // Example of using a whitelisted email and legitimate source/destination IP
            
            // Check system integrity after login attempts
            ids.checkSystemIntegrity();
            
            // Check network traffic
            ids.checkNetworkTraffic(1200); // Example of unusually large network traffic
        } else {
            logger.severe("System integrity compromised. Immediate action required.");
        }
        
        // Initiate password recovery
        boolean recoveryInitiated = ids.initiatePasswordRecovery("user1");
        
        if (recoveryInitiated) {
            System.out.println("Password recovery initiated successfully.");
        } else {
            System.out.println("Failed to initiate password recovery. User not found or email address not available.");
        }
        
        // Reset password (assume the reset token and new password are obtained from the reset link)
        String resetToken = "randomResetToken123";
        String newPassword = "newPassword123";
        boolean passwordReset = ids.resetPassword("user1", resetToken, newPassword);
        
        if (passwordReset) {
            System.out.println("Password reset successfully.");
        } else {
            System.out.println("Failed to reset password. Invalid reset token.");
        }
    }
}

