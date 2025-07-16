import yaml
import os
import json
from typing import List, Dict, Any, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import re
from loguru import logger

class SecurityRequirementType(Enum):
    """Types of security requirements that can be extracted from manifests"""
    PRIVILEGED = "privileged"
    ROOT_USER = "root_user"
    HOST_NETWORK = "host_network"
    HOST_PID = "host_pid"
    HOST_IPC = "host_ipc"
    HOST_PATH = "host_path"
    CAPABILITIES = "capabilities"
    SELINUX = "selinux"
    FSGROUP = "fsgroup"
    SUPPLEMENTAL_GROUPS = "supplemental_groups"
    SECCOMP = "seccomp"
    APPARMOR = "apparmor"
    VOLUMES = "volumes"
    PORTS = "ports"
    RESOURCE_LIMITS = "resource_limits"

@dataclass
class SecurityRequirement:
    """Represents a security requirement extracted from a manifest"""
    requirement_type: SecurityRequirementType
    value: Any
    resource_name: str
    resource_kind: str
    namespace: str
    context: str
    severity: str = "medium"  # low, medium, high, critical
    
    def __post_init__(self):
        # Determine severity based on requirement type
        critical_requirements = {
            SecurityRequirementType.PRIVILEGED,
            SecurityRequirementType.HOST_NETWORK,
            SecurityRequirementType.HOST_PID,
            SecurityRequirementType.HOST_IPC
        }
        
        high_requirements = {
            SecurityRequirementType.ROOT_USER,
            SecurityRequirementType.HOST_PATH,
            SecurityRequirementType.CAPABILITIES
        }
        
        if self.requirement_type in critical_requirements:
            self.severity = "critical"
        elif self.requirement_type in high_requirements:
            self.severity = "high"

@dataclass
class ServiceAccountInfo:
    """Information about service accounts used in manifests"""
    name: str
    namespace: str
    resources: List[str] = field(default_factory=list)
    
@dataclass
class ManifestAnalysis:
    """Result of manifest analysis"""
    file_path: str
    resources: List[Dict[str, Any]]
    security_requirements: List[SecurityRequirement]
    service_accounts: List[ServiceAccountInfo]
    namespaces: Set[str]
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

class ManifestParser:
    """Parser for Kubernetes/OpenShift YAML manifests"""
    
    def __init__(self):
        self.supported_kinds = {
            'Pod', 'Deployment', 'ReplicaSet', 'StatefulSet', 'DaemonSet',
            'Job', 'CronJob', 'DeploymentConfig', 'ServiceAccount',
            'Secret', 'ConfigMap', 'PersistentVolumeClaim', 'Service',
            'Route', 'Ingress', 'NetworkPolicy', 'PodSecurityPolicy',
            'SecurityContextConstraints', 'Role', 'RoleBinding',
            'ClusterRole', 'ClusterRoleBinding'
        }
        
        self.workload_kinds = {
            'Pod', 'Deployment', 'ReplicaSet', 'StatefulSet', 'DaemonSet',
            'Job', 'CronJob', 'DeploymentConfig'
        }
    
    def parse_file(self, file_path: str) -> ManifestAnalysis:
        """Parse a single YAML file"""
        logger.info(f"Parsing manifest file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Handle multi-document YAML files
            documents = list(yaml.safe_load_all(content))
            
            resources = []
            security_requirements = []
            service_accounts = []
            namespaces = set()
            errors = []
            warnings = []
            
            for doc in documents:
                if not doc or not isinstance(doc, dict):
                    continue
                
                try:
                    # Extract basic resource info
                    kind = doc.get('kind', '')
                    metadata = doc.get('metadata', {})
                    resource_name = metadata.get('name', 'unknown')
                    namespace = metadata.get('namespace', 'default')
                    
                    if kind not in self.supported_kinds:
                        warnings.append(f"Unsupported resource kind: {kind}")
                        continue
                    
                    resources.append(doc)
                    namespaces.add(namespace)
                    
                    # Extract security requirements
                    if kind in self.workload_kinds:
                        reqs = self._extract_security_requirements(doc)
                        security_requirements.extend(reqs)
                    
                    # Extract service account info
                    if kind == 'ServiceAccount':
                        # Check if we already have this service account
                        existing_sa = next((sa for sa in service_accounts if sa.name == resource_name and sa.namespace == namespace), None)
                        if not existing_sa:
                            sa_info = ServiceAccountInfo(
                                name=resource_name,
                                namespace=namespace
                            )
                            service_accounts.append(sa_info)
                    elif kind in self.workload_kinds:
                        sa_name = self._extract_service_account(doc)
                        if sa_name:
                            # Check if we already have this service account
                            existing_sa = next((sa for sa in service_accounts if sa.name == sa_name and sa.namespace == namespace), None)
                            if existing_sa:
                                existing_sa.resources.append(f"{kind}/{resource_name}")
                            else:
                                sa_info = ServiceAccountInfo(
                                    name=sa_name,
                                    namespace=namespace,
                                    resources=[f"{kind}/{resource_name}"]
                                )
                                service_accounts.append(sa_info)
                
                except Exception as e:
                    errors.append(f"Error processing resource: {str(e)}")
            
            return ManifestAnalysis(
                file_path=file_path,
                resources=resources,
                security_requirements=security_requirements,
                service_accounts=service_accounts,
                namespaces=namespaces,
                errors=errors,
                warnings=warnings
            )
            
        except Exception as e:
            logger.error(f"Error parsing file {file_path}: {str(e)}")
            return ManifestAnalysis(
                file_path=file_path,
                resources=[],
                security_requirements=[],
                service_accounts=[],
                namespaces=set(),
                errors=[f"Failed to parse file: {str(e)}"]
            )
    
    def parse_directory(self, directory_path: str) -> List[ManifestAnalysis]:
        """Parse all YAML files in a directory"""
        logger.info(f"Parsing manifests in directory: {directory_path}")
        
        results = []
        yaml_extensions = {'.yaml', '.yml'}
        
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if any(file.endswith(ext) for ext in yaml_extensions):
                    file_path = os.path.join(root, file)
                    analysis = self.parse_file(file_path)
                    results.append(analysis)
        
        return results
    
    def _extract_security_requirements(self, resource: Dict[str, Any]) -> List[SecurityRequirement]:
        """Extract security requirements from a workload resource"""
        requirements = []
        
        kind = resource.get('kind', '')
        metadata = resource.get('metadata', {})
        resource_name = metadata.get('name', 'unknown')
        namespace = metadata.get('namespace', 'default')
        
        # Get pod template spec
        pod_spec = self._get_pod_spec(resource)
        if not pod_spec:
            return requirements
        
        # Check security context at pod level
        security_context = pod_spec.get('securityContext', {})
        
        # Check for privileged containers
        containers = pod_spec.get('containers', []) + pod_spec.get('initContainers', [])
        for container in containers:
            container_name = container.get('name', 'unknown')
            container_security_context = container.get('securityContext', {})
            
            # Privileged container
            if container_security_context.get('privileged', False):
                requirements.append(SecurityRequirement(
                    requirement_type=SecurityRequirementType.PRIVILEGED,
                    value=True,
                    resource_name=resource_name,
                    resource_kind=kind,
                    namespace=namespace,
                    context=f"container/{container_name}"
                ))
            
            # Root user
            run_as_user = container_security_context.get('runAsUser', security_context.get('runAsUser'))
            if run_as_user == 0:
                requirements.append(SecurityRequirement(
                    requirement_type=SecurityRequirementType.ROOT_USER,
                    value=0,
                    resource_name=resource_name,
                    resource_kind=kind,
                    namespace=namespace,
                    context=f"container/{container_name}"
                ))
            
            # Capabilities
            capabilities = container_security_context.get('capabilities', {})
            if capabilities.get('add'):
                requirements.append(SecurityRequirement(
                    requirement_type=SecurityRequirementType.CAPABILITIES,
                    value=capabilities['add'],
                    resource_name=resource_name,
                    resource_kind=kind,
                    namespace=namespace,
                    context=f"container/{container_name}"
                ))
        
        # Host network, PID, IPC
        if pod_spec.get('hostNetwork', False):
            requirements.append(SecurityRequirement(
                requirement_type=SecurityRequirementType.HOST_NETWORK,
                value=True,
                resource_name=resource_name,
                resource_kind=kind,
                namespace=namespace,
                context="pod"
            ))
        
        if pod_spec.get('hostPID', False):
            requirements.append(SecurityRequirement(
                requirement_type=SecurityRequirementType.HOST_PID,
                value=True,
                resource_name=resource_name,
                resource_kind=kind,
                namespace=namespace,
                context="pod"
            ))
        
        if pod_spec.get('hostIPC', False):
            requirements.append(SecurityRequirement(
                requirement_type=SecurityRequirementType.HOST_IPC,
                value=True,
                resource_name=resource_name,
                resource_kind=kind,
                namespace=namespace,
                context="pod"
            ))
        
        # Host path volumes
        volumes = pod_spec.get('volumes', [])
        for volume in volumes:
            if 'hostPath' in volume:
                requirements.append(SecurityRequirement(
                    requirement_type=SecurityRequirementType.HOST_PATH,
                    value=volume['hostPath']['path'],
                    resource_name=resource_name,
                    resource_kind=kind,
                    namespace=namespace,
                    context=f"volume/{volume.get('name', 'unknown')}"
                ))
        
        # FSGroup
        fs_group = security_context.get('fsGroup')
        if fs_group is not None:
            requirements.append(SecurityRequirement(
                requirement_type=SecurityRequirementType.FSGROUP,
                value=fs_group,
                resource_name=resource_name,
                resource_kind=kind,
                namespace=namespace,
                context="pod"
            ))
        
        # Supplemental groups
        supplemental_groups = security_context.get('supplementalGroups', [])
        if supplemental_groups:
            requirements.append(SecurityRequirement(
                requirement_type=SecurityRequirementType.SUPPLEMENTAL_GROUPS,
                value=supplemental_groups,
                resource_name=resource_name,
                resource_kind=kind,
                namespace=namespace,
                context="pod"
            ))
        
        # SELinux
        se_linux_options = security_context.get('seLinuxOptions')
        if se_linux_options:
            requirements.append(SecurityRequirement(
                requirement_type=SecurityRequirementType.SELINUX,
                value=se_linux_options,
                resource_name=resource_name,
                resource_kind=kind,
                namespace=namespace,
                context="pod"
            ))
        
        return requirements
    
    def _get_pod_spec(self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract pod spec from different resource types"""
        kind = resource.get('kind', '')
        
        if kind == 'Pod':
            return resource.get('spec', {})
        elif kind in {'Deployment', 'ReplicaSet', 'StatefulSet', 'DaemonSet'}:
            return resource.get('spec', {}).get('template', {}).get('spec', {})
        elif kind == 'DeploymentConfig':
            return resource.get('spec', {}).get('template', {}).get('spec', {})
        elif kind in {'Job', 'CronJob'}:
            if kind == 'Job':
                return resource.get('spec', {}).get('template', {}).get('spec', {})
            else:  # CronJob
                return resource.get('spec', {}).get('jobTemplate', {}).get('spec', {}).get('template', {}).get('spec', {})
        
        return None
    
    def _extract_service_account(self, resource: Dict[str, Any]) -> Optional[str]:
        """Extract service account name from a workload resource"""
        pod_spec = self._get_pod_spec(resource)
        if pod_spec:
            return pod_spec.get('serviceAccountName') or pod_spec.get('serviceAccount')
        return None
    
    def combine_analyses(self, analyses: List[ManifestAnalysis]) -> ManifestAnalysis:
        """Combine multiple manifest analyses into a single result"""
        if not analyses:
            return ManifestAnalysis(
                file_path="combined",
                resources=[],
                security_requirements=[],
                service_accounts=[],
                namespaces=set()
            )
        
        combined_resources = []
        combined_security_requirements = []
        combined_service_accounts = []
        combined_namespaces = set()
        combined_errors = []
        combined_warnings = []
        
        for analysis in analyses:
            combined_resources.extend(analysis.resources)
            combined_security_requirements.extend(analysis.security_requirements)
            combined_service_accounts.extend(analysis.service_accounts)
            combined_namespaces.update(analysis.namespaces)
            combined_errors.extend(analysis.errors)
            combined_warnings.extend(analysis.warnings)
        
        # Deduplicate service accounts
        unique_service_accounts = []
        seen_sa = set()
        for sa in combined_service_accounts:
            sa_key = (sa.name, sa.namespace)
            if sa_key not in seen_sa:
                seen_sa.add(sa_key)
                unique_service_accounts.append(sa)
            else:
                # Merge resources
                existing_sa = next(existing for existing in unique_service_accounts if existing.name == sa.name and existing.namespace == sa.namespace)
                existing_sa.resources.extend(sa.resources)
                existing_sa.resources = list(set(existing_sa.resources))  # Remove duplicates
        
        return ManifestAnalysis(
            file_path="combined",
            resources=combined_resources,
            security_requirements=combined_security_requirements,
            service_accounts=unique_service_accounts,
            namespaces=combined_namespaces,
            errors=combined_errors,
            warnings=combined_warnings
        )
    
    def get_analysis_summary(self, analysis: ManifestAnalysis) -> Dict[str, Any]:
        """Get a summary of the analysis results"""
        requirement_counts = {}
        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        
        for req in analysis.security_requirements:
            req_type = req.requirement_type.value
            requirement_counts[req_type] = requirement_counts.get(req_type, 0) + 1
            severity_counts[req.severity] += 1
        
        return {
            "total_resources": len(analysis.resources),
            "total_security_requirements": len(analysis.security_requirements),
            "total_service_accounts": len(analysis.service_accounts),
            "namespaces": list(analysis.namespaces),
            "requirement_counts": requirement_counts,
            "severity_counts": severity_counts,
            "errors": len(analysis.errors),
            "warnings": len(analysis.warnings),
            "service_accounts": [
                {
                    "name": sa.name,
                    "namespace": sa.namespace,
                    "resources": sa.resources
                }
                for sa in analysis.service_accounts
            ]
        } 

    def extract_existing_rbac_resources(self, file_path: str) -> Dict[str, Any]:
        """
        Extract existing RBAC resources (SCC, ClusterRole, RoleBinding) from manifest
        
        Returns:
            Dict with keys: scc, cluster_roles, role_bindings, cluster_role_bindings
        """
        logger.info(f"Extracting existing RBAC resources from: {file_path}")
        
        rbac_resources = {
            "scc": None,
            "cluster_roles": [],
            "role_bindings": [],
            "cluster_role_bindings": []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            documents = list(yaml.safe_load_all(content))
            
            for doc in documents:
                if not doc or not isinstance(doc, dict):
                    continue
                
                kind = doc.get('kind', '')
                metadata = doc.get('metadata', {})
                resource_name = metadata.get('name', '')
                
                if kind == 'SecurityContextConstraints':
                    rbac_resources["scc"] = {
                        "name": resource_name,
                        "manifest": doc
                    }
                elif kind == 'ClusterRole':
                    rbac_resources["cluster_roles"].append({
                        "name": resource_name,
                        "manifest": doc
                    })
                elif kind == 'RoleBinding':
                    rbac_resources["role_bindings"].append({
                        "name": resource_name,
                        "namespace": metadata.get('namespace', 'default'),
                        "manifest": doc
                    })
                elif kind == 'ClusterRoleBinding':
                    rbac_resources["cluster_role_bindings"].append({
                        "name": resource_name,
                        "manifest": doc
                    })
        
        except Exception as e:
            logger.error(f"Error extracting RBAC resources from {file_path}: {str(e)}")
        
        return rbac_resources 