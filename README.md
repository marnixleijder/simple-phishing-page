# Phishing page

Welcome to my phishing page repository! 🚀

This repository contains a lightweight phishing script built with PHP, featuring enhanced security measures, JSON-based logging, real-time Telegram notifications and session management.

## 📌 About
This phishing script is a single-page platform designed to capture login data with advanced logging and notification capabilities. It includes a basic login template, robust anti-crawler protections, and session timeout features to simulate a secure environment while collecting data.

For any adjustments, tips or custom landing pages, please visit the contact page at [marnixleijder.github.io](https://marnixleijder.github.io/).

## 🛠️ Features
1. **Single-page phishing platform**
   - Real-time notifications on Telegram
   - Clean URL routing (`/` and `/login`)
   - Automatic redirect after data collection
   - Anti-crawler system with user agent and IP range blocking
   - JSON-based logging system
   - Basic Google login page template

2. **Security measures**
   - Rate limiting based on IP (5 attempts in 60 seconds) with Telegram alerts
   - IP-based request throttling
   - Automatic IP blocking for crawlers and blacklisted ranges
   - Request sanitization with `htmlspecialchars` for user inputs and user agent
   - Security headers (HSTS, XSS, NoSniff, X-Frame-Options)
   - HTTPS enforcement
   - Secure file permissions for logs directory
   - Session timeout (30 minutes) with automatic renewal on activity

3. **JSON logging system**
   - JSON Lines (`.jsonl`) format for all logs
   - Separate logs for page visits (`page_visits.jsonl`), invalid routes (`invalid_routes.jsonl`), blocked IPs/crawlers (`blocked_ips.jsonl`), and IP rate limiting (`ip_log.jsonl`)
   - Detailed logging including IP address, user agent, OS, device, HTTP method and full URL with query strings (e.g., `/login?12345`)
   - Session ID tracking for user actions

4. **Telegram integration**
   - Configurable notification toggle (`$sendTelegramNotifications`)
   - Real-time notifications via Telegram API with retry mechanism (up to 3 attempts)
   - Alerts for:
     - Login page opens (with session ID, IP, user agent, device, method, and URL)
     - Successful logins (with full credentials and metadata)
     - Rate limit exceedances
     - Blocked IPs and crawlers

## 🛠️ Technical stack
- PHP
- WhichBrowser Parser (via Composer) for device detection
- cURL for Telegram API integration
- HTML5 (for login template)
- Apache (server with mod_rewrite and SSL support)
