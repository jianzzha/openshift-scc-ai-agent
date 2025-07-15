# OpenShift SCC AI Agent

An intelligent AI-powered tool for analyzing Kubernetes/OpenShift YAML manifests, generating Security Context Constraints (SCCs), and automatically adjusting SCCs based on deployment failures.

## Features

- **🔍 Intelligent Manifest Analysis**: Analyzes YAML manifests to extract security requirements
- **🛡️ SCC Generation**: Automatically generates Security Context Constraints based on manifest requirements
- **🤖 AI-Powered Adjustments**: Uses OpenAI/Anthropic to analyze deployment failures and suggest SCC fixes
- **⚡ Auto-Deployment**: Automatically deploys manifests with iterative SCC adjustment
- **🔧 OpenShift Integration**: Direct integration with OpenShift clusters
- **📊 Rich CLI Interface**: Beautiful command-line interface with progress bars and tables
- **🎯 Security-First**: Follows principle of least privilege in SCC generation

## Installation

### Prerequisites

- Python 3.8 or higher
- OpenShift CLI (`oc`) installed and configured
- Valid OpenShift cluster access
- OpenAI API key (for AI features)

### Install Dependencies

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

### Setup Environment

You can configure the application using environment variables or a configuration file:

**Option 1: Environment Variables**
```bash
# Required for AI features
export OPENAI_API_KEY=your-openai-api-key

# Optional: specify kubeconfig location
export KUBECONFIG=~/.kube/config
```

**Option 2: Configuration File**
```bash
# Copy the example configuration file
cp config.example.yaml config.yaml

# Edit with your settings
nano config.yaml
```

## Running the Application

You can run the CLI application in several ways:

### Method 1: Direct execution with virtual environment
```bash
# Activate virtual environment and run
source venv/bin/activate
python main.py --help
```

### Method 2: Using the shell script wrapper (Linux/macOS)
```bash
# Make the script executable (one-time setup)
chmod +x run.sh

# Run the application
./run.sh --help
./run.sh analyze examples/nginx-deployment.yaml
./run.sh generate-scc examples/nginx-deployment.yaml --scc-name nginx-scc
```

### Method 3: Install as a package (optional)
```bash
# Install in development mode
pip install -e .

# Run from anywhere
scc-ai-agent --help
```

## Quick Start

### 1. Analyze Manifests

```bash
python main.py analyze examples/sample-deployment.yaml
```

### 2. Generate SCC

```bash
python main.py generate-scc examples/sample-deployment.yaml -n my-app-scc
```

### 3. Deploy with AI Assistance

```bash
python main.py auto-deploy examples/sample-deployment.yaml --ai-provider openai
```

## Command Reference

### Core Commands

#### `analyze`
Analyze YAML manifests and extract security requirements.

```bash
python main.py analyze <path> [OPTIONS]

Options:
  -o, --output PATH        Output file for analysis report
  -f, --format [json|yaml|table]  Output format (default: table)
```

#### `generate-scc`
Generate Security Context Constraints from manifest analysis.

```bash
python main.py generate-scc <manifest_path> -n <scc_name> [OPTIONS]

Options:
  -n, --scc-name TEXT      Name for the generated SCC (required)
  -o, --output PATH        Output file for SCC
  -s, --suggest-existing   Suggest existing SCC instead of creating new
  --optimize              Optimize the generated SCC
```

#### `auto-deploy`
Automatically deploy manifests with AI-powered SCC adjustment.

```bash
python main.py auto-deploy <manifest_path> [OPTIONS]

Options:
  -n, --scc-name TEXT      Name of SCC to create/update
  -k, --kubeconfig PATH    Path to kubeconfig file
  --ai-provider [openai|anthropic|mistral]  AI provider (default: openai)
  --api-key TEXT          API key for AI provider
  --max-iterations INT    Maximum AI adjustment iterations (default: 3)
```

### Cluster Management

#### `connect`
Connect to OpenShift cluster.

```bash
python main.py connect [OPTIONS]

Options:
  -k, --kubeconfig PATH          Path to kubeconfig file
  --kubeconfig-content TEXT      Kubeconfig content as string
  --test-connection             Test connection only
```

#### `deploy`
Deploy manifests to OpenShift cluster.

```bash
python main.py deploy <manifest_path> [OPTIONS]

Options:
  -n, --namespace TEXT     Target namespace
  --dry-run               Perform dry-run deployment
  -k, --kubeconfig PATH   Path to kubeconfig file
  --wait                  Wait for deployment to complete
```

#### `get-scc`
Get SCC from cluster.

```bash
python main.py get-scc <scc_name> [OPTIONS]

Options:
  -k, --kubeconfig PATH   Path to kubeconfig file
  -o, --output PATH       Output file for SCC
```

#### `list-sccs`
List all SCCs in cluster.

```bash
python main.py list-sccs [OPTIONS]

Options:
  -k, --kubeconfig PATH   Path to kubeconfig file
  -o, --output PATH       Output file for SCC list
```

## Project Structure

```
openshift-scc-ai-agent/
├── src/
│   ├── yaml_parser/           # YAML manifest parsing
│   │   └── manifest_parser.py
│   ├── scc_manager/           # SCC generation and management
│   │   └── scc_generator.py
│   ├── openshift_client/      # OpenShift cluster interaction
│   │   └── client.py
│   ├── ai_agent/              # AI-powered analysis
│   │   └── scc_ai_agent.py
│   └── cli/                   # Command-line interface
│       └── main.py
├── tests/                     # Test files
├── examples/                  # Example manifests
├── docs/                      # Documentation
├── main.py                    # Main entry point
├── requirements.txt           # Dependencies
└── README.md                  # This file
```

## Usage Examples

### Example 1: Basic Analysis

```bash
# Analyze a single manifest file
python main.py analyze examples/nginx-deployment.yaml

# Analyze all manifests in a directory
python main.py analyze examples/ --format json --output analysis.json
```

### Example 2: SCC Generation

```bash
# Generate SCC for a deployment
python main.py generate-scc examples/nginx-deployment.yaml -n nginx-scc

# Suggest existing SCC instead of creating new one
python main.py generate-scc examples/nginx-deployment.yaml --suggest-existing

# Generate optimized SCC
python main.py generate-scc examples/nginx-deployment.yaml -n nginx-scc --optimize
```

### Example 3: AI-Powered Deployment

```bash
# Deploy with AI assistance
python main.py auto-deploy examples/nginx-deployment.yaml \
  --ai-provider openai \
  --scc-name nginx-scc \
  --max-iterations 5

# Deploy to specific namespace
python main.py deploy examples/nginx-deployment.yaml -n my-namespace
```

### Example 4: Cluster Management

```bash
# Connect to cluster
python main.py connect -k ~/.kube/config

# List all SCCs
python main.py list-sccs

# Get specific SCC
python main.py get-scc restricted -o restricted-scc.yaml
```

## Security Requirements Analysis

The tool analyzes manifests for various security requirements:

### Critical Requirements
- **Privileged containers**: `privileged: true`
- **Host network access**: `hostNetwork: true`
- **Host PID access**: `hostPID: true`
- **Host IPC access**: `hostIPC: true`

### High-Risk Requirements
- **Root user**: `runAsUser: 0`
- **Host path volumes**: `hostPath` volumes
- **Additional capabilities**: `capabilities.add`

### Medium-Risk Requirements
- **Specific user/group IDs**: `runAsUser`, `runAsGroup`, `fsGroup`
- **SELinux contexts**: `seLinuxOptions`
- **Supplemental groups**: `supplementalGroups`

### Low-Risk Requirements
- **Resource limits**: CPU/memory limits
- **Standard volumes**: ConfigMaps, Secrets, EmptyDir
- **Network policies**: Standard networking

## AI Analysis Features

### Deployment Failure Analysis
- Analyzes deployment error messages
- Identifies SCC-related issues
- Suggests specific SCC adjustments
- Provides security impact assessment

### SCC Optimization
- Identifies over-permissioned SCCs
- Suggests tightening unused permissions
- Recommends security improvements
- Provides gradual optimization approach

### AI Providers Support
- **OpenAI**: GPT-4 for comprehensive analysis
- **Anthropic**: Claude for security-focused analysis (planned)
- **Mistral**: Open-source alternative (planned)
- **Local**: Self-hosted models (planned)

## Configuration

### Environment Variables

```bash
# AI Configuration
export OPENAI_API_KEY=your-openai-api-key
export ANTHROPIC_API_KEY=your-anthropic-api-key

# Cluster Configuration
export KUBECONFIG=~/.kube/config

# Logging
export LOG_LEVEL=INFO
```

### Kubeconfig Setup

The tool supports multiple ways to provide cluster credentials:

1. **Default kubeconfig**: `~/.kube/config`
2. **Custom kubeconfig**: `--kubeconfig /path/to/config`
3. **Inline kubeconfig**: `--kubeconfig-content "apiVersion: v1..."`
4. **Environment variable**: `KUBECONFIG=/path/to/config`

## Security Considerations

### SCC Generation Principles
1. **Least Privilege**: Start with minimal permissions
2. **Requirement-Based**: Only grant necessary permissions
3. **Security-First**: Prefer security over convenience
4. **Audit Trail**: Track all permission grants

### AI Safety Measures
1. **Confidence Scoring**: Only apply high-confidence suggestions
2. **Human Review**: Always review AI suggestions
3. **Incremental Changes**: Make small, testable adjustments
4. **Rollback Support**: Easy rollback of changes

## Troubleshooting

### Common Issues

#### 1. Connection Failures
```bash
# Test connection
python main.py connect --test-connection

# Check kubeconfig
oc whoami
```

#### 2. Permission Errors
```bash
# Check cluster permissions
oc auth can-i create securitycontextconstraints

# Use cluster-admin or scc-admin role
oc adm policy add-cluster-role-to-user cluster-admin myuser
```

#### 3. AI Analysis Failures
```bash
# Check API key
echo $OPENAI_API_KEY

# Enable verbose logging
python main.py --verbose auto-deploy examples/app.yaml
```

### Debug Mode

```bash
# Enable verbose logging
python main.py --verbose <command>

# Check logs
tail -f logs/scc-ai-agent.log
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Run linting
flake8 src/
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- 📚 Documentation: `docs/`
- 🐛 Issues: GitHub Issues
- 💬 Discussions: GitHub Discussions
- 📧 Email: support@example.com

## Roadmap

### Planned Features
- [ ] Support for Pod Security Standards (PSS)
- [ ] Integration with ArgoCD/Flux
- [ ] Web UI interface
- [ ] Policy templates
- [ ] Compliance reporting
- [ ] Multi-cluster support

### AI Enhancements
- [ ] Support for Anthropic Claude
- [ ] Local model integration
- [ ] Fine-tuned security models
- [ ] Automated security scoring

## Acknowledgments

- OpenShift team for SCC architecture
- Kubernetes SIG-Security for security standards
- OpenAI for AI capabilities
- Rich library for beautiful CLI interface 