# Changelog

All notable changes to the KLogs Viewer project will be documented in this file.

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

## [0.0.1] - 2025-03-11

### Added
- Initial release of KLogs Viewer
- Web interface for browsing Kubernetes pod logs
- Download logs directly from browser
- Status indicators for pod states
- Multi-container support
- Dark mode support
- Optional token-based authentication