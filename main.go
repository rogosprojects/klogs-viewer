package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Version is the current version of the application.
// It will be overridden during build when using ldflags.
var Version = "dev"

//go:embed templates/*.html
var templateFS embed.FS

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
	Name       string
	LogLink    string
	StreamLink string
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

// CORS/WebSocket configuration
var allowedOrigins string

func init() {
	validToken = os.Getenv("TOKEN")
	labels = os.Getenv("POD_LABELS")
	namespace = os.Getenv("NAMESPACE")
	replaceLabel = os.Getenv("REPLACE_LABEL")
	allowedOrigins = os.Getenv("ALLOWED_ORIGINS")

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

// TemplateData holds the data needed to render the template
type TemplateData struct {
	Version string
	Pods    map[string][]PodInfo
}

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

func createStreamLink(namespace, podName, containerName string, token string) string {
	// URL encode path components to prevent injection
	namespace = url.PathEscape(namespace)
	podName = url.PathEscape(podName)
	containerName = url.PathEscape(containerName)

	streamLink := fmt.Sprintf("/logs/stream/%s/%s/%s", namespace, podName, containerName)

	if token != "" {
		streamLink += fmt.Sprintf("?t=%s", url.QueryEscape(token))
	}

	return streamLink
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
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self' ws: wss:;")

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
					Name:       container.Name,
					LogLink:    createLogLink(pod.Namespace, pod.Name, container.Name, token),
					StreamLink: createStreamLink(pod.Namespace, pod.Name, container.Name, token),
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

	// Prepare template data
	data := TemplateData{
		Version: Version,
		Pods:    podsByLabel,
	}

	// Parse the template from the embedded file system
	tmpl, err := template.New("index.html").Funcs(funcMap).ParseFS(templateFS, "templates/index.html")
	if err != nil {
		log.Printf("Template parsing error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
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

func (s *LogServer) handleStreamLogs(w http.ResponseWriter, r *http.Request) {
	// Validate HTTP method to only allow GET requests
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set security headers
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
	cleanPath := path.Clean(strings.TrimPrefix(r.URL.Path, "/logs/stream/"))
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

	// Parse tail lines if specified in the query
	tailLines := int64(100) // Default to 100 lines
	if tailParam := r.URL.Query().Get("tail"); tailParam != "" {
		if parsed, err := strconv.ParseInt(tailParam, 10, 64); err == nil && parsed > 0 {
			tailLines = parsed
		}
	}

	// Check for WebSocket protocol
	if websocket.IsWebSocketUpgrade(r) {
		s.handleWebSocketLogs(w, r, namespace, podName, containerName, tailLines)
		return
	}

	// If not WebSocket, proceed with traditional HTTP streaming
	// Set headers for live streaming with proper content type
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate") // Prevent caching
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Transfer-Encoding", "chunked") // Ensure chunked encoding

	// Use follow option to stream logs with additional options
	logOptions := &v1.PodLogOptions{
		Container: containerName,
		Follow:    true,       // Follow the log stream in real time
		TailLines: &tailLines, // Start with recent logs
	}

	req := s.clientset.CoreV1().Pods(namespace).GetLogs(podName, logOptions)

	// Create a timeout context (30 min max for streaming)
	streamCtx, cancelStream := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancelStream()

	podLogs, err := req.Stream(streamCtx)
	if err != nil {
		log.Printf("Error getting logs stream for %s/%s/%s: %v", namespace, podName, containerName, err)
		http.Error(w, "Error retrieving container logs", http.StatusInternalServerError)
		return
	}
	defer podLogs.Close()

	// Enable streaming response
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Use io.Copy with a custom writer that flushes after each write
	flushWriter := &flushResponseWriter{w: w, flusher: flusher}

	// Set up rate limiting for high-volume logs (10MB/s max)
	logLimiter := rate.NewLimiter(10*1024*1024, 1024*1024) // 10MB/s with 1MB burst

	// Copy with rate limiting
	done := make(chan struct{})
	go func() {
		defer close(done)

		// Use a larger buffer for efficiency
		buf := make([]byte, 32*1024)

		for {
			select {
			case <-streamCtx.Done():
				return
			default:
				n, err := podLogs.Read(buf)
				if err != nil {
					if err == io.EOF {
						return
					}
					log.Printf("Error reading log stream: %v", err)
					return
				}

				if n > 0 {
					// Apply rate limiting
					if err := logLimiter.WaitN(streamCtx, n); err != nil {
						log.Printf("Rate limiting error: %v", err)
						return
					}

					if _, err := flushWriter.Write(buf[:n]); err != nil {
						log.Printf("Error writing to response: %v", err)
						return
					}
				}
			}
		}
	}()

	// Wait for streaming to complete
	select {
	case <-r.Context().Done():
		// Client disconnected
		cancelStream() // Signal to the streaming goroutine to stop
		<-done         // Wait for the goroutine to finish
	case <-done:
		// Streaming completed
	}
}

// handleWebSocketLogs handles log streaming via WebSockets for longer connections
func (s *LogServer) handleWebSocketLogs(w http.ResponseWriter, r *http.Request, namespace, podName, containerName string, tailLines int64) {
	// Upgrade the HTTP connection to a WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade to WebSocket: %v", err)
		return
	}
	defer conn.Close()

	// Set up a ping/pong handler to keep connection alive
	conn.SetPingHandler(func(message string) error {
		err := conn.WriteControl(websocket.PongMessage, []byte(message), time.Now().Add(10*time.Second))
		if err == websocket.ErrCloseSent {
			return nil
		} else if e, ok := err.(net.Error); ok && e.Temporary() {
			return nil
		}
		return err
	})

	// Create a much longer context timeout for WebSocket connections (4 hours)
	streamCtx, cancelStream := context.WithTimeout(r.Context(), 4*time.Hour)
	defer cancelStream()

	// Use follow option to stream logs
	logOptions := &v1.PodLogOptions{
		Container: containerName,
		Follow:    true,
		TailLines: &tailLines,
	}

	req := s.clientset.CoreV1().Pods(namespace).GetLogs(podName, logOptions)
	podLogs, err := req.Stream(streamCtx)
	if err != nil {
		log.Printf("Error getting logs stream for WebSocket %s/%s/%s: %v", namespace, podName, containerName, err)
		conn.WriteMessage(websocket.TextMessage, []byte("Error retrieving container logs: "+err.Error()))
		return
	}
	defer podLogs.Close()

	// Start a goroutine to read from the WebSocket (client messages)
	stopChan := make(chan struct{})
	go func() {
		defer close(stopChan)
		for {
			// Read message from browser (client might send commands)
			_, msg, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("WebSocket read error: %v", err)
				}
				return
			}

			// Process client messages
			if string(msg) == "close" {
				log.Printf("Received close signal from client for %s/%s/%s", namespace, podName, containerName)
				return // Exit goroutine and close connection gracefully
			}
			// Process other messages like ping
		}
	}()

	// Create a ticker for sending ping messages to keep the connection alive
	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	// Set up rate limiting for high-volume logs (5MB/s max for WebSockets)
	logLimiter := rate.NewLimiter(5*1024*1024, 512*1024) // 5MB/s with 512KB burst

	// Buffer for reading logs
	buf := make([]byte, 16*1024)
	lineBuf := make([]byte, 0, 16*1024) // For accumulating partial lines

	// Process logs and send over WebSocket
	for {
		select {
		case <-stopChan:
			// Client disconnected
			return
		case <-pingTicker.C:
			// Send ping to keep connection alive
			if err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second)); err != nil {
				log.Printf("Failed to send ping: %v", err)
				return
			}
		default:
			// Read from log stream
			n, err := podLogs.Read(buf)
			if err != nil {
				if err == io.EOF {
					// Wait a bit before closing to see if more logs come in
					select {
					case <-stopChan:
						return
					case <-time.After(5 * time.Second):
						// If pod is still running, maybe more logs will come
						continue
					}
				}
				log.Printf("Error reading log stream for WebSocket: %v", err)
				conn.WriteMessage(websocket.TextMessage, []byte("Log stream ended: "+err.Error()))
				return
			}

			if n > 0 {
				// Apply rate limiting
				if err := logLimiter.WaitN(streamCtx, n); err != nil {
					log.Printf("Rate limiting error: %v", err)
					return
				}

				// Process and send logs in complete lines when possible
				lineBuf = append(lineBuf, buf[:n]...)
				lines := bytes.Split(lineBuf, []byte("\n"))

				// Send all complete lines
				if len(lines) > 1 {
					// All lines except the last one are complete
					for i := 0; i < len(lines)-1; i++ {
						// Send each complete line as a separate WebSocket message
						if len(lines[i]) > 0 {
							if err := conn.WriteMessage(websocket.TextMessage, append(lines[i], '\n')); err != nil {
								log.Printf("Error writing to WebSocket: %v", err)
								return
							}
						}
					}

					// Keep the last (potentially incomplete) line in the buffer
					lineBuf = lines[len(lines)-1]
				}
			}
		}
	}
}

// flushResponseWriter wraps an http.ResponseWriter and flushes after each write
type flushResponseWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func (fw *flushResponseWriter) Write(p []byte) (n int, err error) {
	n, err = fw.w.Write(p)
	if err == nil {
		fw.flusher.Flush()
	}
	return
}

// WebSocket configuration
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// Get the Origin header
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // Allow requests with no origin (like curl or direct API calls)
		}

		// Parse the origin URL
		u, err := url.Parse(origin)
		if err != nil {
			log.Printf("Invalid WebSocket origin format: %s", origin)
			return false // Reject invalid origins
		}

		// Get allowed origins from environment variable
		allowedOriginsEnv := os.Getenv("ALLOWED_ORIGINS")
		if allowedOriginsEnv == "" {
			// If not configured, only allow same-origin requests
			host := r.Host
			return u.Host == host
		}

		// Check against comma-separated list of allowed origins
		allowedOrigins := strings.Split(allowedOriginsEnv, ",")
		for _, allowed := range allowedOrigins {
			allowed = strings.TrimSpace(allowed)
			if allowed == "*" {
				return true // Explicitly configured to allow all origins
			}

			if u.Host == allowed || strings.HasSuffix(u.Host, "."+allowed) {
				return true
			}
		}

		// Log rejected origins for monitoring
		log.Printf("Rejected WebSocket connection from origin: %s", origin)
		return false
	},
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
	http.HandleFunc("/logs/stream/", server.rateLimit(server.handleStreamLogs))

	log.Printf("Server starting on: 8080")
	log.Printf("Namespace: %s", namespace)
	log.Print("Token protection: ", protected)
	log.Printf("Rate limiting: %.1f requests per minute per IP with burst of %d", rateLimit, burst)

	// Log WebSocket security configuration
	if allowedOrigins == "" {
		log.Printf("WebSocket origin checking: Enabled (same-origin only)")
	} else if allowedOrigins == "*" {
		log.Printf("WebSocket origin checking: Disabled (all origins allowed)")
	} else {
		log.Printf("WebSocket origin checking: Enabled (allowed origins: %s)", allowedOrigins)
	}

	log.Fatal(http.ListenAndServe(":8080", nil))
}
