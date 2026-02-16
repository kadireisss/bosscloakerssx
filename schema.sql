-- ============================================
-- BOSS Cloaker - MySQL Database Schema
-- Plesk/PHP Compatible Version
-- ============================================

CREATE DATABASE IF NOT EXISTS `boss_cloaker` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `boss_cloaker`;

-- Admin users
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(255) NOT NULL UNIQUE,
    `password` VARCHAR(255) NOT NULL,
    `email` VARCHAR(255) DEFAULT NULL,
    `last_login` DATETIME DEFAULT NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Landing pages (Safe pages)
CREATE TABLE IF NOT EXISTS `landing_pages` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(255) NOT NULL,
    `html_content` LONGTEXT NOT NULL,
    `css_content` LONGTEXT DEFAULT NULL,
    `js_content` LONGTEXT DEFAULT NULL,
    `thumbnail` TEXT DEFAULT NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Domains/Links configuration
CREATE TABLE IF NOT EXISTS `domains` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `domain` VARCHAR(255) NOT NULL UNIQUE,
    `slug` VARCHAR(50) UNIQUE,
    `target_url` TEXT NOT NULL,
    `landing_page_id` INT DEFAULT NULL,
    `redirect_enabled` TINYINT(1) DEFAULT 1,
    `detection_level` VARCHAR(20) DEFAULT 'high',
    `status` VARCHAR(20) DEFAULT 'active',
    `allowed_countries` TEXT DEFAULT NULL,
    `blocked_countries` TEXT DEFAULT NULL,
    `block_direct_access` TINYINT(1) DEFAULT 0,
    `blocked_platforms` VARCHAR(500) DEFAULT 'google,facebook,bing,tiktok',
    `js_challenge` TINYINT(1) DEFAULT 0,
    `redirect_mode` VARCHAR(10) DEFAULT '302',
    `active_hours` VARCHAR(20) DEFAULT NULL,
    `active_days` VARCHAR(50) DEFAULT NULL,
    `timezone` VARCHAR(50) DEFAULT 'Europe/Istanbul',
    `max_clicks_per_ip` INT DEFAULT 0,
    `rate_limit_window` INT DEFAULT 3600,
    `allow_mobile` TINYINT(1) DEFAULT 1,
    `allow_desktop` TINYINT(1) DEFAULT 1,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (`landing_page_id`) REFERENCES `landing_pages`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Rate limit tracking
CREATE TABLE IF NOT EXISTS `rate_limits` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `domain_id` INT DEFAULT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `click_count` INT DEFAULT 1,
    `first_click` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `last_click` DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON DELETE CASCADE,
    INDEX `idx_rate_domain_ip` (`domain_id`, `ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- JS Challenge tokens
CREATE TABLE IF NOT EXISTS `challenge_tokens` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `token` VARCHAR(64) NOT NULL UNIQUE,
    `domain_id` INT DEFAULT NULL,
    `ip_address` VARCHAR(45) DEFAULT NULL,
    `user_agent` TEXT DEFAULT NULL,
    `verified` TINYINT(1) DEFAULT 0,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `expires_at` DATETIME DEFAULT NULL,
    FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON DELETE CASCADE,
    INDEX `idx_challenge_token` (`token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- IP Blacklist
CREATE TABLE IF NOT EXISTS `ip_blacklist` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `ip_address` VARCHAR(45) NOT NULL,
    `reason` TEXT DEFAULT NULL,
    `added_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_ip_address` (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- User-Agent Blacklist
CREATE TABLE IF NOT EXISTS `user_agent_blacklist` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `pattern` TEXT NOT NULL,
    `reason` TEXT DEFAULT NULL,
    `added_at` DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Access Logs
CREATE TABLE IF NOT EXISTS `access_logs` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `domain_id` INT DEFAULT NULL,
    `ip_address` VARCHAR(45) DEFAULT NULL,
    `user_agent` TEXT DEFAULT NULL,
    `asn` VARCHAR(50) DEFAULT NULL,
    `country` VARCHAR(10) DEFAULT NULL,
    `is_bot` TINYINT(1) DEFAULT NULL,
    `bot_score` INT DEFAULT NULL,
    `bot_reasons` TEXT DEFAULT NULL,
    `destination` VARCHAR(20) DEFAULT NULL,
    `headers` JSON DEFAULT NULL,
    `tls_fingerprint` VARCHAR(255) DEFAULT NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON DELETE CASCADE,
    INDEX `idx_log_domain` (`domain_id`),
    INDEX `idx_log_created` (`created_at`),
    INDEX `idx_log_ip` (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Settings
CREATE TABLE IF NOT EXISTS `settings` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `setting_key` VARCHAR(255) UNIQUE NOT NULL,
    `setting_value` TEXT DEFAULT NULL,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
