package main

import (
	"bufio"
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

const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
	<title>Pods Downloader</title>
	<style>
		body {
			font-family: Arial, sans-serif;
			margin: 20px;
			background-color: #f5f5f5;
		}
		.label-container {
			display: grid;
			grid-template-columns: repeat(2, 1fr);
			gap: 30px;
		}
		.label-section {
			background: white;
			padding: 20px;
			border-radius: 8px;
			box-shadow: 0 2px 4px rgba(0,0,0,0.1);
		}
		.label-title {
			color: #333;
			margin-bottom: 20px;
			padding-bottom: 10px;
			border-bottom: 2px solid #eee;
		}
		.pod-grid {
			display: grid;
			grid-template-columns: repeat(2, 1fr);
			gap: 15px;
			padding: 10px;
		}
		.pod-item {
			border-radius: 6px;
			padding: 15px;
			min-height: 100px;
			display: flex;
			flex-direction: column;
			justify-content: space-between;
			cursor: pointer;
			transition: transform 0.2s;
			text-decoration: none;
			color: white;
		}
		.pod-item:hover {
			transform: translateY(-2px);
			box-shadow: 0 4px 8px rgba(0,0,0,0.2);
		}
		.pod-name {
			font-weight: bold;
			margin-bottom: 8px;
		}
		.pod-namespace {
			font-size: 0.8em;
			opacity: 0.8;
		}
		.status-running { background-color: #28a745; }
		.status-pending { background-color: #ffc107; color: #333; }
		.status-failed { background-color: #dc3545; }
		.status-unknown { background-color: #6c757d; }
		.status-succeeded { background-color: #17a2b8; }
		.status-terminated { background-color: #343a40; }
	</style>
</head>
<body>
	<p>Click on a container name to download the logs, Pods are listed by labels.</p>
	<div class="legend">
		<div class="legend-title">Pod Color Legend:</div>
		<ul>
			<li style="color: #dc3545;">Red - Error</li>
			<li style="color: #28a745;">Green - Running</li>
			<li style="color: #ffc107;">Yellow - Pending</li>
			<li style="color: #6c757d;">Gray - Unknown</li>
			<li style="color: #17a2b8;">Blue - Succeeded</li>
			<li style="color: #343a40;">Black - Terminated</li>
		</ul>
	</div>
	<div class="label-container">
	{{range $label, $pods := .}}
	<div class="label-section">
		<h4 class="label-title">{{$label | CleanLabel}}</h4>
		<div class="pod-grid">
		{{range $pods}}
		<div class="pod-item status-{{.Status | ToLower}}">
			<div class="pod-name">{{.Name}}</div>
			<div class="pod-namespace">{{.Namespace}}</div>
			{{range .Containers}}
			<a href="{{.LogLink}}" class="container-link">{{.Name}}</a>
			{{end}}
		</div>
		{{else}}
		<div class="pod-item status-unknown">No pods found</div>
		{{end}}
		</div>
	</div>
	{{end}}
	</div>
</body>
</html>
`

// deprecated, use an environment variable instead
func readLabelsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var labels []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) != "" {
			labels = append(labels, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return labels, nil
}

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
