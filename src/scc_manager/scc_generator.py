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