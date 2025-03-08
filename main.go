package main

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Version is the current version of the application.
// It will be overridden during build when using ldflags.
var Version = "dev"

// LogServer handles the serving of Kubernetes pod logs through HTTP endpoints
type LogServer struct {
	clientset *kubernetes.Clientset
	namespace string
	protected bool
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

var validToken string
var labels string
var namespace string
var protected bool
var replaceLabel string

func init() {
	validToken = os.Getenv("TOKEN")
	labels = os.Getenv("POD_LABELS")
	namespace = os.Getenv("NAMESPACE")
	replaceLabel = os.Getenv("REPLACE_LABEL")

	protected = len(validToken) > 0
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

	return &LogServer{clientset: clientset, namespace: namespace, protected: protected}, nil
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
		<h1>KLogs Viewer</h1>
		<p>View and download container logs directly from your browser. Select a container below to download its logs.</p>
		<div style="position: absolute; top: 1rem; right: 1rem; background-color: var(--primary); color: white; padding: 0.5rem 1rem; border-radius: 1rem; font-size: 0.875rem;">
			v` + Version + `
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

func validateToken(token string) bool {

	if token == validToken {
		return true
	}

	return false
}

func createLogLink(namespace, podName, containerName string, token string) string {

	logLink := fmt.Sprintf("/logs/download/%s/%s/%s", namespace, podName, containerName)

	if token != "" {
		logLink += fmt.Sprintf("?t=%s", token)
	}

	return logLink
}

func (s *LogServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	podsByLabel := make(map[string][]PodInfo)

	if labels == "" {
		log.Fatalf("Failed to read labels from environment variable: %v", labels)
	}

	token := r.URL.Query().Get("t")
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if s.protected {
		if token == "" {
			http.Error(w, "Missing token query parameter", http.StatusBadRequest)
			return
		}

		if !validateToken(token) {
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

func (s *LogServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	if s.protected {
		token := r.URL.Query().Get("t")
		if token == "" {
			http.Error(w, "Missing token query parameter", http.StatusBadRequest)
			return
		}

		if !validateToken(token) {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
	}

	parts := strings.Split(r.URL.Path[15:], "/") // todo: use a safer way to split the URL
	if len(parts) != 3 {
		http.Error(w, "Invalid URL format", http.StatusBadRequest)
		return
	}

	namespace := parts[0]
	podName := parts[1]
	containerName := parts[2]

	req := s.clientset.CoreV1().Pods(namespace).GetLogs(podName, &v1.PodLogOptions{Container: containerName})
	podLogs, err := req.Stream(context.TODO())
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting logs: %v", err), http.StatusInternalServerError)
		return
	}
	defer podLogs.Close()

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s-%s-%s.log", namespace, podName, containerName))
	io.Copy(w, podLogs)
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

	http.HandleFunc("/logs/", server.handleIndex)
	http.HandleFunc("/logs/download/", server.handleLogs)

	log.Printf("Server starting on :8080")
	log.Printf("Namespace: %s", namespace)
	log.Print("Token protection: ", protected)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
