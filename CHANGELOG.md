# Changelog

All notable changes to the KLogs Viewer project will be documented in this file.

## [0.1.0] - 2025-05-05

### User Interface
- Completely redesigned UI with a single table layout for all pods and containers
- Added quick filters for namespaces and labels
- Improved container grouping to show multiple containers from the same pod together
- Optimized space usage throughout the interface

## [0.0.21] - 2025-03-28

### Security
- Implemented proper WebSocket origin checking to prevent cross-site WebSocket hijacking
- Added ALLOWED_ORIGINS environment variable to configure allowed WebSocket origins
- Defaulted to same-origin policy when no origins are explicitly configured
- Added detailed logging of rejected WebSocket connection attempts


### Added
- Implemented client-side search functionality to filter pods
- Added search input in the top-right corner of the header
- Search filters by pod name, namespace, status, and container names
- Dynamic UI updates that hide empty sections during search
- Added clear button and ESC key support for resetting search

### User Experience
- Improved search experience with real-time filtering
- Added "No results" message when search has no matches
- Enhanced responsive design for search on mobile devices

## [0.0.20] - 2025-03-27

### Added
- Implemented WebSocket support for long-lived log streaming connections (up to 4 hours)
- Added in-browser log streaming modal with real-time updates
- Created unified UI with download and stream buttons in the same row
- Enhanced log streaming performance with optimized buffer handling
- Automatic fallback to HTTP streaming for browsers without WebSocket support

### Security
- Updated Content Security Policy to support WebSockets and inline scripts
- Implemented ping/pong mechanism to maintain connection health
- Added rate limiting for WebSocket connections to prevent abuse

### Performance
- Improved log streaming efficiency with line buffering
- Added configurable timeouts for different connection types

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