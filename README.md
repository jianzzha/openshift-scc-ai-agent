# OpenShift SCC AI Agent

An intelligent AI-powered tool for analyzing Kubernetes/OpenShift YAML manifests, generating Security Context Constraints (SCCs), and automatically adjusting SCCs based on deployment failures.

## Features

- **🔍 Intelligent Manifest Analysis**: Analyzes YAML manifests to extract security requirements
- **🛡️ SCC Generation**: Automatically generates Security Context Constraints based on manifest requirements
- **🔄 Smart SCC Updates**: Detects existing SCCs and updates them instead of creating duplicates
- **🤖 AI-Powered Adjustments**: Uses OpenAI (currently supported) to analyze deployment failures and suggest SCC fixes
- **⚡ Auto-Deployment**: Automatically deploys manifests with iterative SCC adjustment
- **🔧 OpenShift Integration**: Direct integration with OpenShift clusters
- **📊 Rich CLI Interface**: Beautiful command-line interface with progress bars and tables
- **🎯 Security-First**: Follows principle of least privilege in SCC generation
- **🔗 Orchestrator Support**: Programmatic API for agent orchestrator integration

## Installation

### Prerequisites

- Python 3.8 or higher
- OpenShift CLI (`oc`) installed and configured
- Valid OpenShift cluster access
- OpenAI API key (for AI-powered features like `auto-deploy`)

> **Note**: OpenAI API key is only required for AI-powered features. Basic manifest analysis and SCC generation work without it.

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
python main.py analyze examples/deployment-with-scc.yaml
```

### 2. Generate SCC

```bash
python main.py generate-scc examples/deployment-with-scc.yaml -n my-app-scc
```

### 3. Deploy with AI Assistance

```bash
python main.py auto-deploy examples/deployment-with-scc.yaml --ai-provider openai
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
│   │   └── scc_generator.py   # Enhanced with SCC update functionality
│   ├── openshift_client/      # OpenShift cluster interaction
│   │   └── client.py          # Enhanced with SCC detection
│   ├── ai_agent/              # AI-powered analysis
│   │   └── scc_ai_agent.py
│   └── cli/                   # Command-line interface
│       └── main.py            # Enhanced with update options
├── tests/                     # Test files
├── examples/                  # Example manifests
│   ├── deployment-with-scc.yaml          # Test deployment with SCC
│   └── deployment-with-scc-updated.yaml  # Enhanced deployment example
├── docs/                      # Documentation
├── main.py                    # Main entry point
├── api_integration_example.py # Agent orchestrator integration example
├── test_scc_update.py         # SCC update functionality tests
├── requirements.txt           # Dependencies
└── README.md                  # This file
```

## New Files and Components

### API Integration Example (`api_integration_example.py`)
A comprehensive example showing how to integrate the SCC AI Agent with orchestrator systems:

```python
from api_integration_example import SCCAgentOrchestrator

orchestrator = SCCAgentOrchestrator(
    kubeconfig_path="~/.kube/config",
    ai_provider="openai"
)

# Smart SCC generation with automatic detection
scc_manifest = orchestrator.generate_scc("my-app.yaml")

# Deploy with AI assistance
results = orchestrator.deploy_with_ai_assistance("my-app.yaml")
```

**Key Methods:**
- `connect_to_cluster()`: Connect to OpenShift cluster
- `analyze_manifests()`: Analyze YAML manifests for security requirements
- `generate_scc()`: Generate or update SCC based on manifest analysis
- `deploy_with_ai_assistance()`: Deploy with AI-powered SCC adjustment
- `get_cluster_sccs()`: Get all SCCs from cluster
- `cleanup_resources()`: Clean up created resources

### Test Examples (`examples/`)
- **`deployment-with-scc.yaml`**: Complete deployment manifest with ServiceAccount, SCC, ClusterRole, RoleBinding, and Deployment
- **`deployment-with-scc-updated.yaml`**: Enhanced version with additional security requirements (hostPath volumes, multiple capabilities)
- **`deployment-with-sufficient-scc.yaml`**: Deployment with comprehensive SCC that already covers all requirements (no updates needed)

### SCC Update Testing (`test_scc_update.py`)
Comprehensive test demonstrating the SCC update functionality:
- Tests detection of existing SCCs
- Verifies permission preservation during updates
- Validates metadata and annotation updates
- Shows progressive security expansion

### SCC No-Update Testing (`test_scc_no_update_needed.py`)
Test demonstrating scenarios where existing SCCs already have sufficient permissions:
- Tests detection of over-permissioned SCCs
- Verifies no unnecessary updates are made
- Compares original vs updated SCC configurations
- Shows efficient permission management

## Enhanced Core Functionality

### OpenShift Client Enhancements (`src/openshift_client/client.py`)

**New Methods:**
- `get_service_account_scc_associations()`: Discovers SCCs associated with service accounts through RoleBindings and ClusterRoleBindings
- `find_existing_scc_for_service_accounts()`: Finds common SCCs used by multiple service accounts
- Enhanced RBAC analysis for SCC detection

**Usage Example:**
```python
from src.openshift_client.client import OpenShiftClient

client = OpenShiftClient()
client.connect()

# Find SCCs associated with service accounts
scc_associations = client.get_service_account_scc_associations(['my-service-account'])

# Find common SCC for multiple service accounts
common_scc = client.find_existing_scc_for_service_accounts(['sa1', 'sa2'], 'namespace')
```

### SCC Generator Enhancements (`src/scc_manager/scc_generator.py`)

**New Methods:**
- `generate_or_update_scc()`: Smart method that detects existing SCCs and updates them instead of creating new ones
- `update_existing_scc_with_requirements()`: Updates existing SCC with new security requirements while preserving existing permissions
- `_scc_manifest_to_configuration()`: Converts SCC manifest to SCCConfiguration object for processing

**Key Features:**
- **Permission Preservation**: Existing SCC permissions are never removed, only extended
- **Metadata Management**: Preserves resourceVersion, uid, creationTimestamp
- **Audit Trail**: Adds `last-updated-by` and `last-updated-at` annotations
- **Intelligent Merging**: Combines requirements from multiple sources

**Usage Example:**
```python
from src.scc_manager.scc_generator import SCCGenerator

generator = SCCGenerator()

# Smart SCC generation - updates existing if found, creates new if not
scc_manifest = generator.generate_or_update_scc(
    security_requirements,
    service_accounts,
    scc_name="my-app-scc",
    namespace="default",
    existing_scc=existing_scc_manifest  # Optional: provide existing SCC
)
```

### CLI Enhancements (`src/cli/main.py`)

**Enhanced `generate-scc` Command:**
```bash
# Smart SCC detection and update (default behavior)
python main.py generate-scc examples/nginx-deployment.yaml -k ~/.kube/config

# New options:
--update-existing      # Update existing SCC if found (default: true)
--force-new           # Force creation of new SCC even if existing ones found
--kubeconfig PATH     # Connect to cluster for SCC detection
```

**Enhanced `auto-deploy` Command:**
- Now uses smart SCC detection by default
- Displays existing SCC associations
- Offers to deploy updated SCCs and RBAC

## Usage Examples

### Example 1: Basic Analysis

```bash
# Analyze a single manifest file
python main.py analyze examples/nginx-deployment.yaml

# Analyze all manifests in a directory
python main.py analyze examples/ --format json --output analysis.json
```

### Example 2: SCC Generation and Updates

```bash
# Smart SCC detection and update (NEW - default behavior)
python main.py generate-scc examples/nginx-deployment.yaml -k ~/.kube/config

# The tool will:
# 1. Analyze the manifest for service accounts
# 2. Check cluster for existing SCCs associated with those service accounts
# 3. Update existing SCCs with new requirements (preserving existing permissions)
# 4. Create new SCC only if no existing association found

# Generate new SCC with specific name
python main.py generate-scc examples/nginx-deployment.yaml -n nginx-scc

# Force creation of new SCC even if existing ones are found
python main.py generate-scc examples/nginx-deployment.yaml --force-new -n nginx-scc

# Suggest existing SCC instead of creating new one
python main.py generate-scc examples/nginx-deployment.yaml --suggest-existing

# Generate optimized SCC
python main.py generate-scc examples/nginx-deployment.yaml -n nginx-scc --optimize
```

**New Smart SCC Detection Features:**

- **Automatic Detection**: The agent now automatically detects existing SCCs associated with service accounts in your manifests
- **Update Existing**: Instead of creating duplicate SCCs, it updates existing ones with new requirements
- **Preserve Permissions**: Existing SCC permissions are preserved and extended with new requirements
- **Intelligent Merging**: Combines requirements from multiple manifests while maintaining security boundaries
- **Audit Trail**: Tracks all changes with metadata annotations (`last-updated-by`, `last-updated-at`)
- **Progressive Security**: Allows gradual permission expansion as applications evolve

**Example Output:**
```
🔍 Analyzing manifest for service accounts...
Found service account: my-app-sa (namespace: default)

🔍 Checking cluster for existing SCC associations...
Found existing SCC: my-app-scc (associated with my-app-sa)

📝 Updating existing SCC with new requirements:
  Current capabilities: [NET_BIND_SERVICE]
  Adding capabilities: [SETUID, CHOWN, SETGID]
  Adding host paths: [/tmp (read-write)]
  Adding volume types: [hostPath]

✅ SCC updated successfully with preserved permissions
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
- **OpenAI**: GPT-4 for comprehensive analysis ✅ **Currently Supported**
- **Anthropic**: Claude for security-focused analysis ⏳ **Planned** (dependencies included)
- **Mistral**: Open-source alternative ⏳ **Planned** (dependencies included)
- **Local**: Self-hosted models ⏳ **Planned**

> **⚠️ Important**: Currently only OpenAI is fully implemented and functional. Other providers are planned for future releases but will show warning messages if used.

## Configuration

### Environment Variables

```bash
# AI Configuration (Required for AI features)
export OPENAI_API_KEY=your-openai-api-key
# export ANTHROPIC_API_KEY=your-anthropic-api-key  # Not yet functional

# Cluster Configuration
export KUBECONFIG=~/.kube/config

# Logging
export LOG_LEVEL=INFO
```

### Using Without AI Features

If you don't have an OpenAI API key, you can still use most features:

```bash
# These commands work without AI:
./run.sh analyze examples/nginx-deployment.yaml
./run.sh generate-scc examples/nginx-deployment.yaml --scc-name nginx-scc
./run.sh connect
./run.sh list-sccs
./run.sh get-scc restricted

# This command requires OpenAI API key:
./run.sh auto-deploy examples/nginx-deployment.yaml  # Uses AI for failure analysis
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
python main.py --verbose auto-deploy examples/deployment-with-scc.yaml
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

## Testing and Validation

### SCC Update Testing
The `test_scc_update.py` script provides comprehensive testing of the SCC update functionality:

```bash
# Run SCC update tests
python test_scc_update.py
```

**Test Coverage:**
- Service account SCC association detection
- Permission preservation during updates
- Metadata and annotation management
- Progressive security requirement addition
- Audit trail validation

### Example Manifests
The `examples/` directory contains test manifests for different scenarios:

1. **Basic Deployment with SCC** (`deployment-with-scc.yaml`):
   - ServiceAccount with SCC association
   - Single capability requirement (`NET_BIND_SERVICE`)
   - Complete RBAC setup

2. **Enhanced Deployment** (`deployment-with-scc-updated.yaml`):
   - Additional capabilities (`SETUID`, `CHOWN`, `SETGID`)
   - Host path volume requirements
   - Demonstrates SCC update scenarios

3. **Sufficient SCC Deployment** (`deployment-with-sufficient-scc.yaml`):
   - Comprehensive SCC with extensive permissions
   - Deployment with minimal security requirements
   - Demonstrates no-update scenarios

**Running Tests:**
```bash
# Test basic deployment
python main.py analyze examples/deployment-with-scc.yaml

# Test enhanced deployment (shows update scenario)
python main.py analyze examples/deployment-with-scc-updated.yaml

# Test deployment with sufficient SCC (no updates needed)
python main.py analyze examples/deployment-with-sufficient-scc.yaml

# Test SCC generation from examples
python main.py generate-scc examples/deployment-with-scc.yaml -n test-scc

# Run comprehensive SCC update tests
python test_scc_update.py

# Run SCC no-update tests
python test_scc_no_update_needed.py
```

## Agent Orchestrator Integration

The OpenShift SCC AI Agent is designed to work seamlessly with agent orchestrators and automation systems. The new smart SCC detection and update functionality is particularly valuable for orchestrated environments.

### Key Features for Agent Orchestrators

1. **Automatic SCC Detection**: Detects existing SCCs associated with service accounts through RoleBindings and ClusterRoleBindings
2. **Smart Updates**: Updates existing SCCs instead of creating duplicates, preserving existing permissions
3. **Programmatic Interface**: Python API for direct integration via `SCCAgentOrchestrator` class
4. **Structured Output**: JSON/YAML output for easy parsing
5. **Stateless Operations**: Each operation is independent and can be orchestrated
6. **Progressive Security**: Allows gradual permission expansion as applications evolve

### Integration Approaches

#### 1. Programmatic Integration
Use the `SCCAgentOrchestrator` class for direct Python integration:

```python
from api_integration_example import SCCAgentOrchestrator

# Initialize orchestrator
orchestrator = SCCAgentOrchestrator(
    kubeconfig_path="~/.kube/config",
    ai_provider="openai",
    api_key=os.getenv("OPENAI_API_KEY")
)

# Connect to cluster
orchestrator.connect_to_cluster()

# Smart SCC generation - automatically detects and updates existing SCCs
scc_manifest = orchestrator.generate_scc("my-app.yaml")

# Deploy with AI assistance
results = orchestrator.deploy_with_ai_assistance("my-app.yaml")

# Get all SCCs from cluster
sccs = orchestrator.get_cluster_sccs()

# Cleanup resources
orchestrator.cleanup_resources(["my-app-scc"])
```

#### 2. CLI Integration
Use the command-line interface for shell-based orchestration:

```bash
# Detect existing SCCs and update them
./run.sh generate-scc my-app.yaml -k ~/.kube/config --format json

# Force new SCC creation if needed
./run.sh generate-scc my-app.yaml --force-new -n my-new-scc

# Auto-deploy with AI assistance
./run.sh auto-deploy my-app.yaml --ai-provider openai --max-iterations 3
```

#### 3. JSON/YAML Output Processing
Parse structured output for decision-making:

```bash
# Get analysis results in JSON format
python main.py analyze my-app.yaml --format json --output analysis.json

# Generate SCC with JSON output
python main.py generate-scc my-app.yaml --format json --output scc.json
```

### Benefits for Orchestrated Environments

- **Prevents SCC Proliferation**: Reuses existing SCCs instead of creating duplicates
- **Maintains Security Boundaries**: Preserves existing permissions while adding new ones
- **Reduces RBAC Complexity**: Minimizes the number of ClusterRoles and RoleBindings
- **Enables Progressive Security**: Allows gradual permission expansion as applications evolve
- **Provides Audit Trail**: Tracks all changes with metadata annotations
- **Supports Rollback**: Easy identification and rollback of changes

### Integration Examples

#### GitOps Integration
```yaml
# ArgoCD/Flux workflow
apiVersion: argoproj.io/v1alpha1
kind: Workflow
spec:
  steps:
  - name: analyze-manifest
    template: scc-analysis
    arguments:
      parameters:
      - name: manifest
        value: "{{workflow.parameters.manifest}}"
  
  - name: generate-scc
    template: scc-generation
    arguments:
      parameters:
      - name: analysis-result
        value: "{{steps.analyze-manifest.outputs.result}}"
```

#### CI/CD Pipeline Integration
```bash
#!/bin/bash
# CI/CD pipeline step

# Analyze manifest
python main.py analyze $MANIFEST_PATH --format json --output analysis.json

# Generate or update SCC
python main.py generate-scc $MANIFEST_PATH \
  --kubeconfig $KUBECONFIG \
  --format json \
  --output scc.json

# Apply to cluster if validation passes
if [ $? -eq 0 ]; then
  kubectl apply -f scc.json
fi
```

### API Reference for Orchestrators

The `SCCAgentOrchestrator` class provides these key methods:

| Method | Description | Returns |
|--------|-------------|---------|
| `connect_to_cluster()` | Connect to OpenShift cluster | `bool` |
| `analyze_manifests(path)` | Analyze YAML manifests | `dict` |
| `generate_scc(manifest_path)` | Generate or update SCC | `dict` |
| `deploy_with_ai_assistance(path)` | Deploy with AI help | `dict` |
| `get_cluster_sccs()` | Get all cluster SCCs | `list` |
| `cleanup_resources(resources)` | Clean up resources | `bool` |

### Error Handling for Orchestrators

The agent provides structured error responses for orchestrator handling:

```python
try:
    result = orchestrator.generate_scc("manifest.yaml")
except Exception as e:
    # Handle errors gracefully
    error_info = {
        "error": str(e),
        "component": "scc-generation",
        "manifest": "manifest.yaml",
        "timestamp": datetime.now().isoformat()
    }
    # Log or handle error appropriately
``` 