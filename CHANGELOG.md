# Changelog

All notable changes to the KLogs Viewer project will be documented in this file.

## [0.0.19] - 2025-03-27

### Security
- Fixed authentication bypass vulnerability in URL path handling (`/logs` vs `/logs/`)
- Implemented constant-time token comparison to prevent timing attacks
- Added method validation to only allow GET requests for log endpoints
- Enhanced token validation logic to prevent security misconfiguration issues
- Improved error logging for authentication failures with client IP tracking
- Added consistent security checks across all endpoints

### Code Quality
- Separated HTML templates from Go code for better maintainability
- Added embedded file system for template storage

## [0.0.17]

### Security
- Fixed path traversal vulnerability in URL handling
- Added URL encoding/decoding for path components to prevent injection attacks
- Improved error handling to prevent information leakage
- Added security headers (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection)
- Implemented Content-Security-Policy for the web interface
- Fixed application crash on missing labels configuration
- Added IP logging for authentication failures
- Added secure headers and cache control for log downloads
- Created proper 404 handler with security headers
### Rate limiting
- Implemented rate limiting to protect against abuse
- Added configurable rate limiting through environment variables:
  - `RATE_LIMIT`: Requests allowed per minute per IP (default: 10)
  - `RATE_BURST`: Maximum burst size (default: 20)
  - `VISITOR_TTL`: Time to keep inactive clients in memory (default: 60 minutes)
  - `CLEANUP_INTERVAL`: Frequency to clean up inactive clients (default: 60 minutes)
- Added proper 429 Too Many Requests responses with Retry-After header

## [0.0.1] - 2025-03-11

### Added
- Initial release of KLogs Viewer
- Web interface for browsing Kubernetes pod logs
- Download logs directly from browser
- Status indicators for pod states
- Multi-container support
- Dark mode support
- Optional token-based authentication