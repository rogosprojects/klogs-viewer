# klogs Viewer

![Go Version](https://img.shields.io/badge/golang-1.23+-blue)
![Kubernetes Version](https://img.shields.io/badge/kubernetes-1.28+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

KLogs Viewer is a lightweight, web-based application that allows you to view and download Kubernetes pod logs directly in your browser. Designed for developers and operators who need quick access to container logs without using the command line.

## ✨ Features

- **Simple Web Interface**: Browse pods organized by labels
- **One-click Downloads**: Download container logs with a single click
- **Status Indicators**: Visual indicators show pod status (Running, Pending, Failed, etc.)
- **Multi-container Support**: Access logs from any container in multi-container pods
- **Dark Mode Support**: Comfortable viewing in any lighting condition
- **Optional Authentication**: Token-based protection for secure deployments

## 🚀 Getting Started

### Deploy with Helm
```bash
helm repo add rogosprojects https://raw.githubusercontent.com/rogosprojects/helm/master

helm repo update

helm install klogs-viewer rogosprojects/klogs-viewer
```

[Read the full chart documentation](./helm/README.md)

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NAMESPACE` | Kubernetes namespace to monitor | Default namespace |
| `POD_LABELS` | Comma-separated list of pod label selectors | `app=*` |
| `TOKEN` | Optional authentication token | (none) |
| `REPLACE_LABEL` | Custom label replacement pattern | `app=` |

## 🔒 Security

When deploying to production, we recommend:

1. Setting the `TOKEN` environment variable for authentication
2. Using a specific namespace rather than cluster-wide access
3. Deploying behind an ingress with TLS


## 🛠️ Building from Source

```bash
# Clone the repository
git clone https://github.com/rogosprojects/klogs-viewer.git
cd klogs-viewer

# Build the Docker image
docker build -t klogs-viewer:latest .

```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.