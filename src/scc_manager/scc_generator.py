import yaml
import json
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from loguru import logger
from ..yaml_parser.manifest_parser import SecurityRequirement, SecurityRequirementType, ManifestAnalysis

class SCCAllowedPolicy(Enum):
    """SCC policy options"""
    MUST_RUN_AS = "MustRunAs"
    MUST_RUN_AS_NON_ROOT = "MustRunAsNonRoot"
    RUN_AS_ANY = "RunAsAny"

@dataclass
class SCCConfiguration:
    """Configuration for Security Context Constraint"""
    name: str
    description: str = ""
    priority: int = 10
    allow_privileged_container: bool = False
    allow_host_network: bool = False
    allow_host_pid: bool = False
    allow_host_ipc: bool = False
    allow_host_ports: bool = False
    allow_host_directives: bool = False
    read_only_root_filesystem: bool = False
    run_as_user: SCCAllowedPolicy = SCCAllowedPolicy.MUST_RUN_AS_NON_ROOT
    run_as_group: SCCAllowedPolicy = SCCAllowedPolicy.MUST_RUN_AS
    se_linux_context: SCCAllowedPolicy = SCCAllowedPolicy.MUST_RUN_AS
    fs_group: SCCAllowedPolicy = SCCAllowedPolicy.MUST_RUN_AS
    supplemental_groups: SCCAllowedPolicy = SCCAllowedPolicy.MUST_RUN_AS
    allowed_capabilities: List[str] = field(default_factory=list)
    required_drop_capabilities: List[str] = field(default_factory=lambda: ["ALL"])
    default_add_capabilities: List[str] = field(default_factory=list)
    allowed_unsafe_sysctls: List[str] = field(default_factory=list)
    forbidden_sysctls: List[str] = field(default_factory=list)
    allowed_volume_types: List[str] = field(default_factory=lambda: [
        "configMap", "downwardAPI", "emptyDir", "persistentVolumeClaim", 
        "projected", "secret"
    ])
    allowed_flex_volumes: List[Dict[str, str]] = field(default_factory=list)
    allowed_host_paths: List[Dict[str, str]] = field(default_factory=list)
    seccomp_profiles: List[str] = field(default_factory=lambda: ["runtime/default"])
    apparmor_profiles: List[str] = field(default_factory=lambda: ["runtime/default"])
    users: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)

class SCCGenerator:
    """Generator for OpenShift Security Context Constraints"""
    
    def __init__(self):
        self.predefined_sccs = {
            "anyuid": self._get_anyuid_scc(),
            "hostaccess": self._get_hostaccess_scc(),
            "hostmount-anyuid": self._get_hostmount_anyuid_scc(),
            "hostnetwork": self._get_hostnetwork_scc(),
            "nonroot": self._get_nonroot_scc(),
            "privileged": self._get_privileged_scc(),
            "restricted": self._get_restricted_scc()
        }
    
    def generate_scc_from_requirements(self, analysis: ManifestAnalysis, scc_name: str) -> Dict[str, Any]:
        """Generate an SCC based on security requirements from manifest analysis"""
        logger.info(f"Generating SCC '{scc_name}' from security requirements")
        
        # Start with a restrictive base configuration
        config = SCCConfiguration(
            name=scc_name,
            description=f"Generated SCC for manifests from {analysis.file_path}",
            priority=10
        )
        
        # Analyze requirements and adjust SCC configuration
        for req in analysis.security_requirements:
            self._apply_requirement_to_scc(config, req)
        
        # Generate the SCC YAML
        scc_yaml = self._generate_scc_yaml(config)
        
        logger.info(f"Generated SCC with {len(analysis.security_requirements)} requirements")
        return scc_yaml
    
    def update_existing_scc_with_requirements(self, existing_scc: Dict[str, Any], analysis: ManifestAnalysis) -> Dict[str, Any]:
        """
        Update an existing SCC with new security requirements
        
        Args:
            existing_scc: Existing SCC manifest
            analysis: Manifest analysis with new requirements
            
        Returns:
            Dict: Updated SCC manifest
        """
        logger.info(f"Updating existing SCC '{existing_scc['metadata']['name']}' with new requirements")
        
        # Convert existing SCC to configuration
        config = self._scc_manifest_to_configuration(existing_scc)
        
        # Apply new requirements to existing configuration
        for req in analysis.security_requirements:
            self._apply_requirement_to_scc(config, req)
        
        # Update description to reflect the merge
        config.description = f"Updated SCC for manifests from {analysis.file_path}"
        
        # Generate updated SCC YAML
        updated_scc = self._generate_scc_yaml(config)
        
        # Preserve important metadata from original SCC
        if existing_scc['metadata'].get('resourceVersion'):
            updated_scc['metadata']['resourceVersion'] = existing_scc['metadata']['resourceVersion']
        if existing_scc['metadata'].get('uid'):
            updated_scc['metadata']['uid'] = existing_scc['metadata']['uid']
        if existing_scc['metadata'].get('creationTimestamp'):
            updated_scc['metadata']['creationTimestamp'] = existing_scc['metadata']['creationTimestamp']
        
        # Add annotation about the update
        if 'annotations' not in updated_scc['metadata']:
            updated_scc['metadata']['annotations'] = {}
        updated_scc['metadata']['annotations']['last-updated-by'] = 'openshift-scc-ai-agent'
        updated_scc['metadata']['annotations']['last-updated-at'] = datetime.now().isoformat()
        
        logger.info(f"Updated SCC with {len(analysis.security_requirements)} additional requirements")
        return updated_scc
    
    def _scc_manifest_to_configuration(self, scc_manifest: Dict[str, Any]) -> SCCConfiguration:
        """
        Convert SCC manifest to SCCConfiguration for easier manipulation
        
        Args:
            scc_manifest: SCC manifest dictionary
            
        Returns:
            SCCConfiguration: Configuration object
        """
        metadata = scc_manifest.get('metadata', {})
        
        # Create configuration from manifest
        config = SCCConfiguration(
            name=metadata.get('name', ''),
            description=metadata.get('annotations', {}).get('description', ''),
            priority=scc_manifest.get('priority', 10)
        )
        
        # Map SCC fields to configuration
        config.allow_privileged_container = scc_manifest.get('allowPrivilegedContainer', False)
        config.allow_host_network = scc_manifest.get('allowHostNetwork', False)
        config.allow_host_pid = scc_manifest.get('allowHostPID', False)
        config.allow_host_ipc = scc_manifest.get('allowHostIPC', False)
        config.allow_host_ports = scc_manifest.get('allowHostPorts', False)
        config.allow_host_directives = scc_manifest.get('allowHostDirVolumePlugin', False)
        config.read_only_root_filesystem = scc_manifest.get('readOnlyRootFilesystem', False)
        
        # Map run as policies
        config.run_as_user = SCCAllowedPolicy(scc_manifest.get('runAsUser', {}).get('type', 'MustRunAsNonRoot'))
        config.run_as_group = SCCAllowedPolicy(scc_manifest.get('runAsGroup', {}).get('type', 'MustRunAs'))
        config.se_linux_context = SCCAllowedPolicy(scc_manifest.get('seLinuxContext', {}).get('type', 'MustRunAs'))
        config.fs_group = SCCAllowedPolicy(scc_manifest.get('fsGroup', {}).get('type', 'MustRunAs'))
        config.supplemental_groups = SCCAllowedPolicy(scc_manifest.get('supplementalGroups', {}).get('type', 'MustRunAs'))
        
        # Map capability lists
        config.allowed_capabilities = list(scc_manifest.get('allowedCapabilities') or [])
        config.required_drop_capabilities = list(scc_manifest.get('requiredDropCapabilities') or ['ALL'])
        config.default_add_capabilities = list(scc_manifest.get('defaultAddCapabilities') or [])
        
        # Map sysctls
        config.allowed_unsafe_sysctls = list(scc_manifest.get('allowedUnsafeSysctls') or [])
        config.forbidden_sysctls = list(scc_manifest.get('forbiddenSysctls') or [])
        
        # Map volumes
        config.allowed_volume_types = list(scc_manifest.get('volumes') or [])
        config.allowed_flex_volumes = list(scc_manifest.get('allowedFlexVolumes') or [])
        config.allowed_host_paths = list(scc_manifest.get('allowedHostPaths') or [])
        
        # Map security profiles
        config.seccomp_profiles = list(scc_manifest.get('seccompProfiles') or ['runtime/default'])
        config.apparmor_profiles = list(scc_manifest.get('apparmor_profiles') or ['runtime/default'])
        
        # Map users and groups
        config.users = list(scc_manifest.get('users') or [])
        config.groups = list(scc_manifest.get('groups') or [])
        
        return config
    
    def generate_or_update_scc(self, analysis: ManifestAnalysis, scc_name: Optional[str] = None, 
                               openshift_client=None, force_new: bool = False) -> Dict[str, Any]:
        """
        Generate new SCC or update existing one based on manifest content and service account associations
        
        Args:
            analysis: Manifest analysis
            scc_name: Preferred SCC name (optional, overrides manifest SCC name)
            openshift_client: OpenShift client for checking existing SCCs
            force_new: Force creation of new SCC even if existing ones found
            
        Returns:
            Dict: SCC manifest (new or updated)
        """
        from ..yaml_parser.manifest_parser import ManifestParser
        
        # First, check if the manifest itself contains an SCC
        parser = ManifestParser()
        rbac_resources = parser.extract_existing_rbac_resources(analysis.file_path)
        manifest_scc = rbac_resources.get("scc")
        
        # Determine SCC name priority:
        # 1. User-provided -n flag (scc_name parameter)
        # 2. SCC name from manifest
        # 3. Auto-generated name
        determined_scc_name = scc_name
        if not determined_scc_name and manifest_scc:
            determined_scc_name = manifest_scc["name"]
            logger.info(f"Using SCC name from manifest: {determined_scc_name}")
        elif not determined_scc_name:
            determined_scc_name = f"generated-{hash(analysis.file_path) % 10000}"
        
        # If manifest has SCC and no -n flag provided, update the manifest SCC
        if manifest_scc and not scc_name and not force_new:
            logger.info(f"Updating existing SCC from manifest: {manifest_scc['name']}")
            return self.update_existing_scc_with_requirements(manifest_scc["manifest"], analysis)
        
        # If force_new is True, create new SCC regardless
        if force_new:
            # For force_new, always generate new name unless explicitly provided by user
            if not scc_name:
                determined_scc_name = f"generated-{hash(analysis.file_path) % 10000}"
            logger.info(f"Force creating new SCC: {determined_scc_name}")
            return self.generate_scc_from_requirements(analysis, determined_scc_name)
        
        # If no OpenShift client provided, generate new SCC
        if not openshift_client:
            logger.info(f"No cluster client provided, generating new SCC: {determined_scc_name}")
            return self.generate_scc_from_requirements(analysis, determined_scc_name)
        
        # Convert service accounts to format expected by client
        service_accounts = [
            {'name': sa.name, 'namespace': sa.namespace} 
            for sa in analysis.service_accounts
        ]
        
        # Try to find existing SCC in cluster
        existing_scc_in_cluster = openshift_client.find_existing_scc_for_service_accounts(service_accounts)
        
        if existing_scc_in_cluster:
            # Update existing SCC from cluster
            logger.info(f"Updating existing SCC from cluster: {existing_scc_in_cluster['metadata']['name']}")
            return self.update_existing_scc_with_requirements(existing_scc_in_cluster, analysis)
        else:
            # Create new SCC
            logger.info(f"Creating new SCC: {determined_scc_name}")
            return self.generate_scc_from_requirements(analysis, determined_scc_name)
    
    def create_rbac_resources_from_manifest(self, analysis: ManifestAnalysis, scc_name: str) -> Dict[str, Any]:
        """
        Create RBAC resources (ClusterRole, RoleBinding) preserving existing names from manifest
        
        Args:
            analysis: Manifest analysis
            scc_name: SCC name to use
            
        Returns:
            Dict with ClusterRole and RoleBinding manifests
        """
        from ..yaml_parser.manifest_parser import ManifestParser
        
        parser = ManifestParser()
        rbac_resources = parser.extract_existing_rbac_resources(analysis.file_path)
        
        # Create ClusterRole
        existing_cluster_role = None
        for cr in rbac_resources["cluster_roles"]:
            if f"system:openshift:scc:{scc_name}" in cr["name"]:
                existing_cluster_role = cr
                break
        
        if existing_cluster_role:
            cluster_role_name = existing_cluster_role["name"]
            logger.info(f"Using existing ClusterRole name: {cluster_role_name}")
        else:
            cluster_role_name = f"system:openshift:scc:{scc_name}"
            logger.info(f"Creating new ClusterRole: {cluster_role_name}")
        
        cluster_role = self.create_clusterrole_with_name(scc_name, cluster_role_name)
        
        # Create RoleBindings for each service account
        role_bindings = []
        for sa in analysis.service_accounts:
            # Check if RoleBinding already exists in manifest
            existing_binding = None
            for rb in rbac_resources["role_bindings"]:
                # Check if this RoleBinding is for this service account and references the SCC
                rb_subjects = rb.get("manifest", {}).get("subjects", [])
                rb_roleref = rb.get("manifest", {}).get("roleRef", {})
                
                # Check if the binding is for this service account
                sa_match = any(
                    subj.get("name") == sa.name and 
                    subj.get("namespace") == sa.namespace and
                    subj.get("kind") == "ServiceAccount"
                    for subj in rb_subjects
                )
                
                # Check if the binding references the SCC's ClusterRole
                role_match = (
                    rb_roleref.get("name") == f"system:openshift:scc:{scc_name}" or
                    scc_name in rb_roleref.get("name", "")
                )
                
                if sa_match and role_match:
                    existing_binding = rb
                    break
            
            if existing_binding:
                binding_name = existing_binding["name"]
                logger.info(f"Using existing RoleBinding name: {binding_name}")
            else:
                binding_name = f"scc-{scc_name}-{sa.name}-{sa.namespace}"
                logger.info(f"Creating new RoleBinding: {binding_name}")
            
            role_binding = self.create_rolebinding_with_name(
                scc_name, sa.name, sa.namespace, binding_name, cluster_role_name
            )
            role_bindings.append(role_binding)
        
        return {
            "cluster_role": cluster_role,
            "role_bindings": role_bindings
        }
    
    def create_clusterrole_with_name(self, scc_name: str, cluster_role_name: str) -> Dict[str, Any]:
        """Create a ClusterRole with specific name"""
        logger.info(f"Creating ClusterRole '{cluster_role_name}' for SCC '{scc_name}'")
        
        cluster_role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {
                "name": cluster_role_name,
                "annotations": {
                    "generated-by": "openshift-scc-ai-agent",
                    "generated-at": datetime.now().isoformat(),
                    "kubernetes.io/description": f"ClusterRole for SCC {scc_name}"
                }
            },
            "rules": [
                {
                    "apiGroups": ["security.openshift.io"],
                    "resources": ["securitycontextconstraints"],
                    "verbs": ["use"],
                    "resourceNames": [scc_name]
                }
            ]
        }
        
        return cluster_role
    
    def create_rolebinding_with_name(self, scc_name: str, service_account: str, namespace: str, 
                                   binding_name: str, cluster_role_name: str) -> Dict[str, Any]:
        """Create a RoleBinding with specific name"""
        logger.info(f"Creating RoleBinding '{binding_name}' for SA '{service_account}' in namespace '{namespace}'")
        
        role_binding = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {
                "name": binding_name,
                "namespace": namespace,
                "annotations": {
                    "generated-by": "openshift-scc-ai-agent",
                    "generated-at": datetime.now().isoformat()
                }
            },
            "subjects": [
                {
                    "kind": "ServiceAccount",
                    "name": service_account,
                    "namespace": namespace
                }
            ],
            "roleRef": {
                "kind": "ClusterRole",
                "name": cluster_role_name,
                "apiGroup": "rbac.authorization.k8s.io"
            }
        }
        
        return role_binding
    
    def _apply_requirement_to_scc(self, config: SCCConfiguration, requirement: SecurityRequirement):
        """Apply a single security requirement to the SCC configuration"""
        req_type = requirement.requirement_type
        
        if req_type == SecurityRequirementType.PRIVILEGED:
            config.allow_privileged_container = True
            config.run_as_user = SCCAllowedPolicy.RUN_AS_ANY
            config.allowed_volume_types.extend(["hostPath", "flexVolume"])
            config.allow_host_directives = True
            
        elif req_type == SecurityRequirementType.ROOT_USER:
            config.run_as_user = SCCAllowedPolicy.RUN_AS_ANY
            
        elif req_type == SecurityRequirementType.HOST_NETWORK:
            config.allow_host_network = True
            config.allow_host_ports = True
            
        elif req_type == SecurityRequirementType.HOST_PID:
            config.allow_host_pid = True
            
        elif req_type == SecurityRequirementType.HOST_IPC:
            config.allow_host_ipc = True
            
        elif req_type == SecurityRequirementType.HOST_PATH:
            if "hostPath" not in config.allowed_volume_types:
                config.allowed_volume_types.append("hostPath")
            
            # Add specific host path
            host_path = {
                "pathPrefix": requirement.value,
                "readOnly": False
            }
            if host_path not in config.allowed_host_paths:
                config.allowed_host_paths.append(host_path)
            
        elif req_type == SecurityRequirementType.CAPABILITIES:
            capabilities = requirement.value if isinstance(requirement.value, list) else [requirement.value]
            for cap in capabilities:
                if cap not in config.allowed_capabilities:
                    config.allowed_capabilities.append(cap)
                # Remove from required drop capabilities if present
                if cap in config.required_drop_capabilities:
                    config.required_drop_capabilities.remove(cap)
            
        elif req_type == SecurityRequirementType.FSGROUP:
            config.fs_group = SCCAllowedPolicy.RUN_AS_ANY
            
        elif req_type == SecurityRequirementType.SUPPLEMENTAL_GROUPS:
            config.supplemental_groups = SCCAllowedPolicy.RUN_AS_ANY
            
        elif req_type == SecurityRequirementType.SELINUX:
            config.se_linux_context = SCCAllowedPolicy.RUN_AS_ANY
            
        elif req_type == SecurityRequirementType.VOLUMES:
            volume_types = requirement.value if isinstance(requirement.value, list) else [requirement.value]
            for vol_type in volume_types:
                if vol_type not in config.allowed_volume_types:
                    config.allowed_volume_types.append(vol_type)
    
    def _generate_scc_yaml(self, config: SCCConfiguration) -> Dict[str, Any]:
        """Generate the actual SCC YAML from configuration"""
        scc = {
            "apiVersion": "security.openshift.io/v1",
            "kind": "SecurityContextConstraints",
            "metadata": {
                "name": config.name,
                "annotations": {
                    "kubernetes.io/description": config.description,
                    "generated-by": "openshift-scc-ai-agent",
                    "generated-at": datetime.now().isoformat()
                }
            },
            "priority": config.priority,
            "allowPrivilegedContainer": config.allow_privileged_container,
            "allowHostNetwork": config.allow_host_network,
            "allowHostPID": config.allow_host_pid,
            "allowHostIPC": config.allow_host_ipc,
            "allowHostPorts": config.allow_host_ports,
            "allowHostDirVolumePlugin": config.allow_host_directives,
            "readOnlyRootFilesystem": config.read_only_root_filesystem,
            "runAsUser": {
                "type": config.run_as_user.value
            },
            "runAsGroup": {
                "type": config.run_as_group.value
            },
            "seLinuxContext": {
                "type": config.se_linux_context.value
            },
            "fsGroup": {
                "type": config.fs_group.value
            },
            "supplementalGroups": {
                "type": config.supplemental_groups.value
            },
            "allowedCapabilities": config.allowed_capabilities,
            "requiredDropCapabilities": config.required_drop_capabilities,
            "defaultAddCapabilities": config.default_add_capabilities,
            "allowedUnsafeSysctls": config.allowed_unsafe_sysctls,
            "forbiddenSysctls": config.forbidden_sysctls,
            "volumes": config.allowed_volume_types,
            "users": config.users,
            "groups": config.groups
        }
        
        # Add conditional fields
        if config.allowed_flex_volumes:
            scc["allowedFlexVolumes"] = config.allowed_flex_volumes
        
        if config.allowed_host_paths:
            scc["allowedHostPaths"] = config.allowed_host_paths
        
        if config.seccomp_profiles:
            scc["seccompProfiles"] = config.seccomp_profiles
        
        # Clean up empty lists and None values
        scc = {k: v for k, v in scc.items() if v is not None and v != []}
        
        return scc
    
    def suggest_existing_scc(self, analysis: ManifestAnalysis) -> Optional[str]:
        """Suggest an existing SCC that might work for the given requirements"""
        logger.info("Analyzing requirements to suggest existing SCC")
        
        # Count severity levels
        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        requirement_types = set()
        
        for req in analysis.security_requirements:
            severity_counts[req.severity] += 1
            requirement_types.add(req.requirement_type)
        
        # Decision logic for existing SCCs
        if not analysis.security_requirements:
            return "restricted"
        
        # Check for critical requirements
        if (SecurityRequirementType.PRIVILEGED in requirement_types or 
            SecurityRequirementType.HOST_NETWORK in requirement_types or
            SecurityRequirementType.HOST_PID in requirement_types or
            SecurityRequirementType.HOST_IPC in requirement_types):
            return "privileged"
        
        # Check for host access requirements
        if SecurityRequirementType.HOST_PATH in requirement_types:
            if SecurityRequirementType.ROOT_USER in requirement_types:
                return "hostmount-anyuid"
            else:
                return "hostaccess"
        
        # Check for network requirements
        if SecurityRequirementType.HOST_NETWORK in requirement_types:
            return "hostnetwork"
        
        # Check for user requirements
        if SecurityRequirementType.ROOT_USER in requirement_types:
            return "anyuid"
        
        # Default to nonroot for other requirements
        if severity_counts["high"] > 0 or severity_counts["critical"] > 0:
            return "nonroot"
        
        return "restricted"
    
    def create_rolebinding(self, scc_name: str, service_account: str, namespace: str) -> Dict[str, Any]:
        """Create a RoleBinding to associate a service account with an SCC"""
        logger.info(f"Creating RoleBinding for SA '{service_account}' in namespace '{namespace}' to SCC '{scc_name}'")
        
        rolebinding = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {
                "name": f"scc-{scc_name}-{service_account}",
                "namespace": namespace,
                "annotations": {
                    "generated-by": "openshift-scc-ai-agent",
                    "generated-at": datetime.now().isoformat()
                }
            },
            "subjects": [
                {
                    "kind": "ServiceAccount",
                    "name": service_account,
                    "namespace": namespace
                }
            ],
            "roleRef": {
                "kind": "ClusterRole",
                "name": f"system:openshift:scc:{scc_name}",
                "apiGroup": "rbac.authorization.k8s.io"
            }
        }
        
        return rolebinding
    
    def create_clusterrole(self, scc_name: str) -> Dict[str, Any]:
        """Create a ClusterRole for the SCC"""
        logger.info(f"Creating ClusterRole for SCC '{scc_name}'")
        
        clusterrole = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {
                "name": f"system:openshift:scc:{scc_name}",
                "annotations": {
                    "generated-by": "openshift-scc-ai-agent",
                    "generated-at": datetime.now().isoformat(),
                    "kubernetes.io/description": f"ClusterRole for SCC {scc_name}"
                }
            },
            "rules": [
                {
                    "apiGroups": ["security.openshift.io"],
                    "resources": ["securitycontextconstraints"],
                    "verbs": ["use"],
                    "resourceNames": [scc_name]
                }
            ]
        }
        
        return clusterrole
    
    def create_clusterrolebinding(self, scc_name: str, service_account: str, namespace: str) -> Dict[str, Any]:
        """Create a ClusterRoleBinding to associate a service account with an SCC"""
        logger.info(f"Creating ClusterRoleBinding for SA '{service_account}' in namespace '{namespace}' to SCC '{scc_name}'")
        
        clusterrolebinding = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {
                "name": f"scc-{scc_name}-{service_account}-{namespace}",
                "annotations": {
                    "generated-by": "openshift-scc-ai-agent",
                    "generated-at": datetime.now().isoformat()
                }
            },
            "subjects": [
                {
                    "kind": "ServiceAccount",
                    "name": service_account,
                    "namespace": namespace
                }
            ],
            "roleRef": {
                "kind": "ClusterRole",
                "name": f"system:openshift:scc:{scc_name}",
                "apiGroup": "rbac.authorization.k8s.io"
            }
        }
        
        return clusterrolebinding
    
    def get_scc_comparison(self, scc1: Dict[str, Any], scc2: Dict[str, Any]) -> Dict[str, Any]:
        """Compare two SCCs and return differences"""
        from deepdiff import DeepDiff
        
        diff = DeepDiff(scc1, scc2, ignore_order=True)
        
        return {
            "added": diff.get("dictionary_item_added", []),
            "removed": diff.get("dictionary_item_removed", []),
            "changed": diff.get("values_changed", {}),
            "type_changed": diff.get("type_changes", {})
        }
    
    def optimize_scc(self, scc: Dict[str, Any], analysis: ManifestAnalysis) -> Dict[str, Any]:
        """Optimize an SCC by removing unnecessary permissions"""
        logger.info(f"Optimizing SCC '{scc['metadata']['name']}'")
        
        optimized_scc = scc.copy()
        
        # Remove unused capabilities
        if "allowedCapabilities" in optimized_scc:
            required_caps = set()
            for req in analysis.security_requirements:
                if req.requirement_type == SecurityRequirementType.CAPABILITIES:
                    caps = req.value if isinstance(req.value, list) else [req.value]
                    required_caps.update(caps)
            
            optimized_scc["allowedCapabilities"] = list(required_caps)
        
        # Remove unused volume types
        if "volumes" in optimized_scc:
            required_volumes = set(["configMap", "downwardAPI", "emptyDir", "persistentVolumeClaim", "projected", "secret"])
            for req in analysis.security_requirements:
                if req.requirement_type == SecurityRequirementType.HOST_PATH:
                    required_volumes.add("hostPath")
                elif req.requirement_type == SecurityRequirementType.VOLUMES:
                    vol_types = req.value if isinstance(req.value, list) else [req.value]
                    required_volumes.update(vol_types)
            
            optimized_scc["volumes"] = list(required_volumes)
        
        return optimized_scc
    
    def _get_anyuid_scc(self) -> Dict[str, Any]:
        """Get the anyuid SCC configuration"""
        return {
            "allowHostDirVolumePlugin": False,
            "allowHostIPC": False,
            "allowHostNetwork": False,
            "allowHostPID": False,
            "allowHostPorts": False,
            "allowPrivilegedContainer": False,
            "allowedCapabilities": [],
            "defaultAddCapabilities": [],
            "fsGroup": {"type": "RunAsAny"},
            "priority": 10,
            "readOnlyRootFilesystem": False,
            "requiredDropCapabilities": ["MKNOD"],
            "runAsUser": {"type": "RunAsAny"},
            "seLinuxContext": {"type": "MustRunAs"},
            "supplementalGroups": {"type": "RunAsAny"},
            "volumes": ["configMap", "downwardAPI", "emptyDir", "persistentVolumeClaim", "projected", "secret"]
        }
    
    def _get_hostaccess_scc(self) -> Dict[str, Any]:
        """Get the hostaccess SCC configuration"""
        return {
            "allowHostDirVolumePlugin": True,
            "allowHostIPC": True,
            "allowHostNetwork": True,
            "allowHostPID": True,
            "allowHostPorts": True,
            "allowPrivilegedContainer": False,
            "allowedCapabilities": [],
            "defaultAddCapabilities": [],
            "fsGroup": {"type": "MustRunAs"},
            "priority": 10,
            "readOnlyRootFilesystem": False,
            "requiredDropCapabilities": ["KILL", "MKNOD", "SETUID", "SETGID"],
            "runAsUser": {"type": "MustRunAsRange"},
            "seLinuxContext": {"type": "MustRunAs"},
            "supplementalGroups": {"type": "RunAsAny"},
            "volumes": ["configMap", "downwardAPI", "emptyDir", "hostPath", "persistentVolumeClaim", "projected", "secret"]
        }
    
    def _get_hostmount_anyuid_scc(self) -> Dict[str, Any]:
        """Get the hostmount-anyuid SCC configuration"""
        return {
            "allowHostDirVolumePlugin": True,
            "allowHostIPC": False,
            "allowHostNetwork": False,
            "allowHostPID": False,
            "allowHostPorts": False,
            "allowPrivilegedContainer": False,
            "allowedCapabilities": [],
            "defaultAddCapabilities": [],
            "fsGroup": {"type": "RunAsAny"},
            "priority": 10,
            "readOnlyRootFilesystem": False,
            "requiredDropCapabilities": ["MKNOD"],
            "runAsUser": {"type": "RunAsAny"},
            "seLinuxContext": {"type": "MustRunAs"},
            "supplementalGroups": {"type": "RunAsAny"},
            "volumes": ["configMap", "downwardAPI", "emptyDir", "hostPath", "persistentVolumeClaim", "projected", "secret"]
        }
    
    def _get_hostnetwork_scc(self) -> Dict[str, Any]:
        """Get the hostnetwork SCC configuration"""
        return {
            "allowHostDirVolumePlugin": False,
            "allowHostIPC": False,
            "allowHostNetwork": True,
            "allowHostPID": False,
            "allowHostPorts": True,
            "allowPrivilegedContainer": False,
            "allowedCapabilities": [],
            "defaultAddCapabilities": [],
            "fsGroup": {"type": "MustRunAs"},
            "priority": 10,
            "readOnlyRootFilesystem": False,
            "requiredDropCapabilities": ["KILL", "MKNOD", "SETUID", "SETGID"],
            "runAsUser": {"type": "MustRunAsRange"},
            "seLinuxContext": {"type": "MustRunAs"},
            "supplementalGroups": {"type": "MustRunAs"},
            "volumes": ["configMap", "downwardAPI", "emptyDir", "persistentVolumeClaim", "projected", "secret"]
        }
    
    def _get_nonroot_scc(self) -> Dict[str, Any]:
        """Get the nonroot SCC configuration"""
        return {
            "allowHostDirVolumePlugin": False,
            "allowHostIPC": False,
            "allowHostNetwork": False,
            "allowHostPID": False,
            "allowHostPorts": False,
            "allowPrivilegedContainer": False,
            "allowedCapabilities": [],
            "defaultAddCapabilities": [],
            "fsGroup": {"type": "RunAsAny"},
            "priority": 10,
            "readOnlyRootFilesystem": False,
            "requiredDropCapabilities": ["KILL", "MKNOD", "SETUID", "SETGID"],
            "runAsUser": {"type": "MustRunAsNonRoot"},
            "seLinuxContext": {"type": "MustRunAs"},
            "supplementalGroups": {"type": "RunAsAny"},
            "volumes": ["configMap", "downwardAPI", "emptyDir", "persistentVolumeClaim", "projected", "secret"]
        }
    
    def _get_privileged_scc(self) -> Dict[str, Any]:
        """Get the privileged SCC configuration"""
        return {
            "allowHostDirVolumePlugin": True,
            "allowHostIPC": True,
            "allowHostNetwork": True,
            "allowHostPID": True,
            "allowHostPorts": True,
            "allowPrivilegedContainer": True,
            "allowedCapabilities": ["*"],
            "defaultAddCapabilities": [],
            "fsGroup": {"type": "RunAsAny"},
            "priority": 10,
            "readOnlyRootFilesystem": False,
            "requiredDropCapabilities": [],
            "runAsUser": {"type": "RunAsAny"},
            "seLinuxContext": {"type": "RunAsAny"},
            "supplementalGroups": {"type": "RunAsAny"},
            "volumes": ["*"]
        }
    
    def _get_restricted_scc(self) -> Dict[str, Any]:
        """Get the restricted SCC configuration"""
        return {
            "allowHostDirVolumePlugin": False,
            "allowHostIPC": False,
            "allowHostNetwork": False,
            "allowHostPID": False,
            "allowHostPorts": False,
            "allowPrivilegedContainer": False,
            "allowedCapabilities": [],
            "defaultAddCapabilities": [],
            "fsGroup": {"type": "MustRunAs"},
            "priority": 10,
            "readOnlyRootFilesystem": False,
            "requiredDropCapabilities": ["KILL", "MKNOD", "SETUID", "SETGID"],
            "runAsUser": {"type": "MustRunAsRange"},
            "seLinuxContext": {"type": "MustRunAs"},
            "supplementalGroups": {"type": "RunAsAny"},
            "volumes": ["configMap", "downwardAPI", "emptyDir", "persistentVolumeClaim", "projected", "secret"]
        } 