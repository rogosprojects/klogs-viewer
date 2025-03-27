package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Version is the current version of the application.
// It will be overridden during build when using ldflags.
var Version = "dev"

// visitor represents a client with rate limiting information
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter manages rate limiting for clients by IP address
type RateLimiter struct {
	visitors map[string]*visitor
	mu       sync.Mutex
	// Configurable parameters for the rate limiter
	rate  rate.Limit
	burst int
	ttl   time.Duration
}

// NewRateLimiter creates a new rate limiter with the specified rate and burst
func NewRateLimiter(r rate.Limit, b int, ttl time.Duration) *RateLimiter {
	return &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     r,
		burst:    b,
		ttl:      ttl,
	}
}

// GetLimiter returns a rate limiter for the specified client IP
func (rl *RateLimiter) GetLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		// Create a new rate limiter for this client
		limiter := rate.NewLimiter(rl.rate, rl.burst)
		rl.visitors[ip] = &visitor{
			limiter:  limiter,
			lastSeen: time.Now(),
		}
		return limiter
	}

	// Update last seen time
	v.lastSeen = time.Now()
	return v.limiter
}

// CleanupVisitors removes visitors that haven't been seen for a while
func (rl *RateLimiter) CleanupVisitors() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	for ip, v := range rl.visitors {
		if time.Since(v.lastSeen) > rl.ttl {
			delete(rl.visitors, ip)
		}
	}
}

// LogServer handles the serving of Kubernetes pod logs through HTTP endpoints
type LogServer struct {
	clientset *kubernetes.Clientset
	namespace string
	protected bool
	limiter   *RateLimiter
}

// PodInfo holds information about a Kubernetes pod and its containers
type PodInfo struct {
	Name       string
	Label      string
	Namespace  string
	Containers []ContainerInfo
	Status     string
}

// ContainerInfo holds information about a container within a pod
type ContainerInfo struct {
	Name    string
	LogLink string
}

// Configuration constants for rate limiting
const (
	// DefaultRateLimit is the default number of requests allowed per minute per IP
	DefaultRateLimit = 10.0
	// DefaultBurst is the default maximum burst size for requests
	DefaultBurst = 20
	// DefaultVisitorTTL is the default time-to-live for inactive visitors in the rate limiter
	DefaultVisitorTTL = 60 // minutes
	// DefaultCleanupInterval is how often we clean up inactive visitors
	DefaultCleanupInterval = 60 // minutes
)

var validToken string
var labels string
var namespace string
var protected bool
var replaceLabel string

// Rate limiting configuration
var rateLimit float64
var burst int
var visitorTTL time.Duration
var cleanupInterval time.Duration

func init() {
	validToken = os.Getenv("TOKEN")
	labels = os.Getenv("POD_LABELS")
	namespace = os.Getenv("NAMESPACE")
	replaceLabel = os.Getenv("REPLACE_LABEL")

	protected = len(validToken) > 0

	// Initialize rate limiting configuration from environment variables
	rateLimit = DefaultRateLimit
	if val := os.Getenv("RATE_LIMIT"); val != "" {
		if parsed, err := strconv.ParseFloat(val, 64); err == nil && parsed > 0 {
			rateLimit = parsed
		}
	}

	burst = DefaultBurst
	if val := os.Getenv("RATE_BURST"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil && parsed > 0 {
			burst = parsed
		}
	}

	visitorTTL = time.Duration(DefaultVisitorTTL) * time.Minute
	if val := os.Getenv("VISITOR_TTL"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil && parsed > 0 {
			visitorTTL = time.Duration(parsed) * time.Minute
		}
	}

	cleanupInterval = time.Duration(DefaultCleanupInterval) * time.Minute
	if val := os.Getenv("CLEANUP_INTERVAL"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil && parsed > 0 {
			cleanupInterval = time.Duration(parsed) * time.Minute
		}
	}
}

func newLogServer(namespace string, protected bool) (*LogServer, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	// Convert requests per minute to requests per second
	requestsPerSecond := rate.Limit(rateLimit / 60.0)

	// Create a rate limiter with the configured parameters
	rateLimiter := NewRateLimiter(requestsPerSecond, burst, visitorTTL)

	// Start a goroutine to cleanup old visitors based on the configured interval
	go func() {
		for {
			time.Sleep(cleanupInterval)
			rateLimiter.CleanupVisitors()
		}
	}()

	return &LogServer{
		clientset: clientset,
		namespace: namespace,
		protected: protected,
		limiter:   rateLimiter,
	}, nil
}

var htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>KLogs Viewer</title>
	<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap">
	<style>
		:root {
			--primary: #3b82f6;
			--primary-hover: #2563eb;
			--running: #10b981;
			--pending: #f59e0b;
			--failed: #ef4444;
			--unknown: #6b7280;
			--succeeded: #06b6d4;
			--terminated: #4b5563;
			--bg-color: #f9fafb;
			--card-bg: #ffffff;
			--text-primary: #111827;
			--text-secondary: #4b5563;
			--border-color: #e5e7eb;
			--shadow-sm: 0 1px 2px 0 rgba(0,0,0,0.05);
			--shadow: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -1px rgba(0,0,0,0.06);
			--shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -2px rgba(0,0,0,0.05);
			--radius: 8px;
		}

		@media (prefers-color-scheme: dark) {
			:root {
				--bg-color: #111827;
				--card-bg: #1f2937;
				--text-primary: #f9fafb;
				--text-secondary: #d1d5db;
				--border-color: #374151;
				--terminated: #94a3b8; /* Lighter color for dark mode */
			}
		}

		* {
			margin: 0;
			padding: 0;
			box-sizing: border-box;
		}

		body {
			font-family: 'Inter', system-ui, -apple-system, sans-serif;
			background-color: var(--bg-color);
			color: var(--text-primary);
			line-height: 1.5;
			padding: 1.5rem;
			max-width: 1440px;
			margin: 0 auto;
		}

		.header {
			margin-bottom: 2rem;
			padding-bottom: 1rem;
			border-bottom: 1px solid var(--border-color);
		}

		.header h1 {
			font-size: 1.875rem;
			font-weight: 700;
			margin-bottom: 0.5rem;
			color: var(--primary);
		}

		.header p {
			color: var(--text-secondary);
		}

		.status-badges {
			display: flex;
			flex-wrap: wrap;
			gap: 0.75rem;
			margin-top: 1.5rem;
			margin-bottom: 2rem;
		}

		.status-badge {
			display: flex;
			align-items: center;
			padding: 0.5rem 1rem;
			border-radius: 2rem;
			font-size: 0.875rem;
			font-weight: 500;
		}

		.status-badge::before {
			content: '';
			display: inline-block;
			width: 0.75rem;
			height: 0.75rem;
			border-radius: 50%;
			margin-right: 0.5rem;
		}

		.status-badge.running { background-color: rgba(16, 185, 129, 0.1); color: var(--running); }
		.status-badge.running::before { background-color: var(--running); }

		.status-badge.pending { background-color: rgba(245, 158, 11, 0.1); color: var(--pending); }
		.status-badge.pending::before { background-color: var(--pending); }

		.status-badge.failed { background-color: rgba(239, 68, 68, 0.1); color: var(--failed); }
		.status-badge.failed::before { background-color: var(--failed); }

		.status-badge.unknown { background-color: rgba(107, 114, 128, 0.1); color: var(--unknown); }
		.status-badge.unknown::before { background-color: var(--unknown); }

		.status-badge.succeeded { background-color: rgba(6, 182, 212, 0.1); color: var(--succeeded); }
		.status-badge.succeeded::before { background-color: var(--succeeded); }

		.status-badge.terminated { background-color: rgba(31, 41, 55, 0.1); color: var(--terminated); }
		.status-badge.terminated::before { background-color: var(--terminated); }

		.label-container {
			display: grid;
			grid-template-columns: repeat(auto-fill, minmax(min(100%, 30rem), 1fr));
			gap: 2rem;
		}

		.label-section {
			background: var(--card-bg);
			border-radius: var(--radius);
			box-shadow: var(--shadow-sm);
			overflow: hidden;
			border: 1px solid var(--border-color);
		}

		.label-title {
			padding: 1.25rem;
			font-size: 1.25rem;
			font-weight: 600;
			background-color: rgba(59, 130, 246, 0.05);
			border-bottom: 1px solid var(--border-color);
		}

		.pod-grid {
			display: grid;
			grid-template-columns: repeat(auto-fill, minmax(min(100%, 15rem), 1fr));
			gap: 1rem;
			padding: 1.25rem;
		}

		.pod-item {
			border-radius: var(--radius);
			padding: 1.25rem;
			display: flex;
			flex-direction: column;
			gap: 0.75rem;
			box-shadow: var(--shadow-sm);
			transition: all 0.2s ease;
			position: relative;
			overflow: hidden;
		}

		.pod-item::before {
			content: '';
			position: absolute;
			top: 0;
			left: 0;
			width: 0.25rem;
			height: 100%;
		}

		.pod-item.status-running::before { background-color: var(--running); }
		.pod-item.status-pending::before { background-color: var(--pending); }
		.pod-item.status-failed::before { background-color: var(--failed); }
		.pod-item.status-unknown::before { background-color: var(--unknown); }
		.pod-item.status-succeeded::before { background-color: var(--succeeded); }
		.pod-item.status-terminated::before { background-color: var(--terminated); }

		.pod-item:hover {
			transform: translateY(-2px);
			box-shadow: var(--shadow);
		}

		.pod-header {
			display: flex;
			flex-direction: column;
			gap: 0.25rem;
		}

		.pod-name {
			font-weight: 600;
			font-size: 1rem;
			white-space: nowrap;
			overflow: hidden;
			text-overflow: ellipsis;
		}

		.pod-namespace {
			font-size: 0.875rem;
			color: var(--text-secondary);
		}

		.pod-status-badge {
			align-self: flex-start;
			font-size: 0.75rem;
			padding: 0.25rem 0.5rem;
			border-radius: 1rem;
			font-weight: 500;
			margin-top: 0.25rem;
		}

		.status-running .pod-status-badge { background-color: rgba(16, 185, 129, 0.1); color: var(--running); }
		.status-pending .pod-status-badge { background-color: rgba(245, 158, 11, 0.1); color: var(--pending); }
		.status-failed .pod-status-badge { background-color: rgba(239, 68, 68, 0.1); color: var(--failed); }
		.status-unknown .pod-status-badge { background-color: rgba(107, 114, 128, 0.1); color: var(--unknown); }
		.status-succeeded .pod-status-badge { background-color: rgba(6, 182, 212, 0.1); color: var(--succeeded); }
		.status-terminated .pod-status-badge { background-color: rgba(75, 85, 99, 0.1); color: var(--terminated); }

		.container-links {
			display: flex;
			flex-direction: column;
			gap: 0.5rem;
			margin-top: 0.5rem;
		}

		.container-link {
			display: inline-flex;
			align-items: center;
			background-color: var(--primary);
			color: white;
			text-decoration: none;
			padding: 0.5rem 1rem;
			border-radius: var(--radius);
			font-size: 0.875rem;
			font-weight: 500;
			transition: background-color 0.2s;
		}

		.container-link:hover {
			background-color: var(--primary-hover);
		}

		.container-link::before {
			content: '⬇';
			margin-right: 0.5rem;
			font-size: 0.75rem;
		}

		.empty-state {
			padding: 2rem;
			text-align: center;
			color: var(--text-secondary);
		}

		@media (max-width: 768px) {
			.label-container {
				grid-template-columns: 1fr;
			}

			.pod-grid {
				grid-template-columns: 1fr;
			}

			.status-badges {
				flex-direction: column;
				align-items: flex-start;
			}
		}
	</style>
</head>
<body>
	<header class="header">
		<h1>KLogs Viewer <span style="position: absolute;padding: 0.5rem 1rem;border-radius: 1rem;font-size: 0.65rem;vertical-align: top;">
			v` + Version + `</span></h1>
		<p>View and download container logs directly from your browser. Select a container below to download its logs.</p>
		</div>
	</header>

	<div class="status-badges">
		<div class="status-badge running">Running</div>
		<div class="status-badge pending">Pending</div>
		<div class="status-badge failed">Failed</div>
		<div class="status-badge unknown">Unknown</div>
		<div class="status-badge succeeded">Succeeded</div>
		<div class="status-badge terminated">Terminated</div>
	</div>

	<div class="label-container">
	{{range $label, $pods := .}}
		<div class="label-section">
			<div class="label-title">{{$label | CleanLabel}}</div>
			{{if $pods}}
			<div class="pod-grid">
				{{range $pods}}
				<div class="pod-item status-{{.Status | ToLower}}">
					<div class="pod-header">
						<div class="pod-name" title="{{.Name}}">{{.Name}}</div>
						<div class="pod-namespace">{{.Namespace}}</div>
						<span class="pod-status-badge">{{.Status}}</span>
					</div>
					<div class="container-links">
						{{range .Containers}}
						<a href="{{.LogLink}}" class="container-link">{{.Name}}</a>
						{{end}}
					</div>
				</div>
				{{end}}
			</div>
			{{else}}
			<div class="empty-state">No pods found for this label</div>
			{{end}}
		</div>
	{{end}}
	</div>
	<footer style="text-align: center; margin-top: 2rem; color: var(--text-secondary);">
	</footer>
</body>
</html>
`

// compareTokens performs a constant-time token comparison to prevent timing attacks
func compareTokens(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func validateToken(token string) bool {
	return compareTokens(token, validToken)
}

func createLogLink(namespace, podName, containerName string, token string) string {
	// URL encode path components to prevent injection
	namespace = url.PathEscape(namespace)
	podName = url.PathEscape(podName)
	containerName = url.PathEscape(containerName)

	logLink := fmt.Sprintf("/logs/download/%s/%s/%s", namespace, podName, containerName)

	if token != "" {
		logLink += fmt.Sprintf("?t=%s", url.QueryEscape(token))
	}

	return logLink
}

func (s *LogServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	// Validate HTTP method to only allow GET requests
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// Handle both /logs and /logs/ paths consistently
	if r.URL.Path != "/logs" && r.URL.Path != "/logs/" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Set security headers
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com;")

	podsByLabel := make(map[string][]PodInfo)

	if labels == "" {
		log.Printf("No labels specified in environment variable")
		http.Error(w, "Application misconfigured - no labels specified", http.StatusInternalServerError)
		return
	}

	// Track client IP for security logging
	clientIP := r.RemoteAddr
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		ips := strings.Split(forwardedFor, ",")
		if len(ips) > 0 {
			clientIP = strings.TrimSpace(ips[0])
		}
	}

	token := r.URL.Query().Get("t")
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if s.protected {
		if token == "" {
			log.Printf("Missing token attempt from %s", clientIP)
			http.Error(w, "Missing token query parameter", http.StatusBadRequest)
			return
		}

		if !validateToken(token) {
			log.Printf("Invalid token attempt from %s for /logs endpoint", clientIP)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
	}

	if s.namespace == "*" {
		s.namespace = metav1.NamespaceAll // Use metav1.NamespaceAll to list pods across all namespaces
	}

	for _, label := range strings.Split(labels, ",") {
		pods, err := s.clientset.CoreV1().Pods(s.namespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: label,
		})
		if err != nil {
			log.Printf("Error listing pods for label %s: %v", label, err)
			continue
		}

		var podInfos []PodInfo
		for _, pod := range pods.Items {
			var containers []ContainerInfo
			for _, container := range pod.Spec.Containers {
				containers = append(containers, ContainerInfo{
					Name:    container.Name,
					LogLink: createLogLink(pod.Namespace, pod.Name, container.Name, token),
				})
			}

			podInfos = append(podInfos, PodInfo{
				Name:       pod.Name,
				Label:      label,
				Namespace:  pod.Namespace,
				Containers: containers,
				Status:     string(pod.Status.Phase),
			})
		}
		podsByLabel[label] = podInfos
	}

	funcMap := template.FuncMap{
		"ToLower": strings.ToLower,
		"CleanLabel": func(label string) string {
			// remove the "app=" prefix from the label
			if replaceLabel != "" {
				return strings.ReplaceAll(label, replaceLabel, "")
			}
			return strings.ReplaceAll(label, "app=", "")
		},
	}

	tmpl := template.Must(template.New("index").Funcs(funcMap).Parse(htmlTemplate))
	if err := tmpl.Execute(w, podsByLabel); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}

// rateLimit implements a middleware function for rate limiting
func (s *LogServer) rateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the IP from the request
		clientIP := r.RemoteAddr

		// Get the X-Forwarded-For header in case this is behind a proxy
		if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
			// Use the first IP in the chain
			ips := strings.Split(forwardedFor, ",")
			if len(ips) > 0 {
				clientIP = strings.TrimSpace(ips[0])
			}
		}

		// Get rate limiter for this client
		limiter := s.limiter.GetLimiter(clientIP)

		// Check if the request is allowed
		if !limiter.Allow() {
			log.Printf("Rate limit exceeded for IP: %s", clientIP)
			w.Header().Set("Retry-After", "60") // Suggest client to retry after 60 seconds
			http.Error(w, "Too many requests. Please try again later.", http.StatusTooManyRequests)
			return
		}

		// Call the next handler if the request is allowed
		next(w, r)
	}
}

func (s *LogServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	// Validate HTTP method to only allow GET requests
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set security headers for downloads
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	clientIP := r.RemoteAddr
	// Get the X-Forwarded-For header in case this is behind a proxy
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		// Use the first IP in the chain
		ips := strings.Split(forwardedFor, ",")
		if len(ips) > 0 {
			clientIP = strings.TrimSpace(ips[0])
		}
	}

	if s.protected {
		token := r.URL.Query().Get("t")
		if token == "" {
			log.Printf("Missing token attempt from %s", clientIP)
			http.Error(w, "Missing token query parameter", http.StatusBadRequest)
			return
		}

		if !validateToken(token) {
			log.Printf("Invalid token attempt from %s", clientIP)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
	}

	// Use safer URL path extraction with path.Clean to prevent path traversal
	cleanPath := path.Clean(strings.TrimPrefix(r.URL.Path, "/logs/download/"))
	parts := strings.Split(cleanPath, "/")
	if len(parts) != 3 {
		http.Error(w, "Invalid URL format", http.StatusBadRequest)
		return
	}

	// URL decode path components
	namespace, err := url.PathUnescape(parts[0])
	if err != nil {
		http.Error(w, "Invalid URL format", http.StatusBadRequest)
		return
	}

	podName, err := url.PathUnescape(parts[1])
	if err != nil {
		http.Error(w, "Invalid URL format", http.StatusBadRequest)
		return
	}

	containerName, err := url.PathUnescape(parts[2])
	if err != nil {
		http.Error(w, "Invalid URL format", http.StatusBadRequest)
		return
	}

	// Basic validation to prevent path traversal
	for _, part := range []string{namespace, podName, containerName} {
		if strings.Contains(part, "..") || strings.Contains(part, "\\") {
			http.Error(w, "Invalid parameter", http.StatusBadRequest)
			return
		}
	}

	req := s.clientset.CoreV1().Pods(namespace).GetLogs(podName, &v1.PodLogOptions{Container: containerName})
	podLogs, err := req.Stream(context.TODO())
	if err != nil {
		// Log detailed error but return generic message to clients
		log.Printf("Error getting logs for %s/%s/%s: %v", namespace, podName, containerName, err)
		http.Error(w, "Error retrieving container logs", http.StatusInternalServerError)
		return
	}
	defer podLogs.Close()

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s-%s-%s.log", namespace, podName, containerName))
	w.Header().Set("X-Content-Type-Options", "nosniff") // Prevent MIME type sniffing
	w.Header().Set("Cache-Control", "no-store")         // Prevent caching of sensitive data
	io.Copy(w, podLogs)
}

// securityHandler adds consistent security checks for all endpoints
func (s *LogServer) securityHandler(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set basic security headers for all responses
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		
		// Only allow GET requests
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		
		// Call the original handler
		handler(w, r)
	}
}

func main() {
	// no need for flags, use environment variables instead
	// namespace := flag.String("namespace", "", "Kubernetes namespace to use")
	// protected := flag.Bool("protected", false, "Protect the application with a token")
	// flag.Parse()

	server, err := newLogServer(namespace, protected)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Set secure HTTP headers for all responses and handle 404s
	http.HandleFunc("/", server.securityHandler(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	}))

	// Apply rate limiting and security checks to all endpoints
	http.HandleFunc("/logs", server.rateLimit(server.handleIndex))
	http.HandleFunc("/logs/", server.rateLimit(server.handleIndex))
	http.HandleFunc("/logs/download/", server.rateLimit(server.handleLogs))

	log.Printf("Server starting on: 8080")
	log.Printf("Namespace: %s", namespace)
	log.Print("Token protection: ", protected)
	log.Printf("Rate limiting: %.1f requests per minute per IP with burst of %d", rateLimit, burst)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
