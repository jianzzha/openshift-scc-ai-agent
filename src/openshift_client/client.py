import os
import yaml
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import tempfile
import time
import subprocess
from loguru import logger
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from openshift.dynamic import DynamicClient
from openshift.dynamic.exceptions import ResourceNotFoundError

@dataclass
class ClusterInfo:
    """Information about the OpenShift cluster"""
    api_url: str
    version: str
    username: str
    namespace: str
    connected: bool = False

@dataclass
class DeploymentResult:
    """Result of a deployment attempt"""
    success: bool
    resource_name: str
    resource_kind: str
    namespace: str
    error_message: Optional[str] = None
    scc_issues: List[str] = None

class OpenShiftClient:
    """Client for interacting with OpenShift clusters"""
    
    def __init__(self, kubeconfig_path: Optional[str] = None):
        """
        Initialize OpenShift client
        
        Args:
            kubeconfig_path: Path to kubeconfig file, defaults to ~/.kube/config
        """
        self.kubeconfig_path = kubeconfig_path or os.path.expanduser("~/.kube/config")
        self.k8s_client = None
        self.dynamic_client = None
        self.cluster_info = None
        self.connected = False
        
    def connect(self, kubeconfig_content: Optional[str] = None) -> bool:
        """
        Connect to OpenShift cluster
        
        Args:
            kubeconfig_content: Optional kubeconfig content as string
            
        Returns:
            bool: True if connection successful
        """
        try:
            if kubeconfig_content:
                # Create temporary kubeconfig file
                with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                    f.write(kubeconfig_content)
                    temp_kubeconfig = f.name
                
                config.load_kube_config(config_file=temp_kubeconfig)
                os.unlink(temp_kubeconfig)
            else:
                config.load_kube_config(config_file=self.kubeconfig_path)
            
            self.k8s_client = client.ApiClient()
            self.dynamic_client = DynamicClient(self.k8s_client)
            
            # Test connection and get cluster info
            self.cluster_info = self._get_cluster_info()
            self.connected = True
            
            logger.info(f"Successfully connected to OpenShift cluster: {self.cluster_info.api_url}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to OpenShift cluster: {str(e)}")
            self.connected = False
            return False
    
    def disconnect(self):
        """Disconnect from cluster"""
        self.k8s_client = None
        self.dynamic_client = None
        self.cluster_info = None
        self.connected = False
        logger.info("Disconnected from OpenShift cluster")
    
    def _get_cluster_info(self) -> ClusterInfo:
        """Get information about the connected cluster"""
        try:
            # Get cluster version
            v1 = client.VersionApi(self.k8s_client)
            version_info = v1.get_code()
            
            # Get current context
            contexts, active_context = config.list_kube_config_contexts()
            api_url = active_context['context']['cluster']
            username = active_context['context'].get('user', 'unknown')
            namespace = active_context['context'].get('namespace', 'default')
            
            return ClusterInfo(
                api_url=api_url,
                version=version_info.git_version,
                username=username,
                namespace=namespace,
                connected=True
            )
            
        except Exception as e:
            logger.warning(f"Could not get cluster info: {str(e)}")
            return ClusterInfo(
                api_url="unknown",
                version="unknown",
                username="unknown",
                namespace="default",
                connected=True
            )
    
    def create_scc(self, scc_manifest: Dict[str, Any]) -> bool:
        """
        Create a Security Context Constraint
        
        Args:
            scc_manifest: SCC manifest as dictionary
            
        Returns:
            bool: True if creation successful
        """
        if not self.connected:
            logger.error("Not connected to cluster")
            return False
        
        try:
            # Get SCC resource
            scc_resource = self.dynamic_client.resources.get(
                api_version="security.openshift.io/v1",
                kind="SecurityContextConstraints"
            )
            
            # Create SCC
            result = scc_resource.create(body=scc_manifest)
            logger.info(f"Created SCC: {result.metadata.name}")
            return True
            
        except ApiException as e:
            if e.status == 409:  # Already exists
                logger.info(f"SCC {scc_manifest['metadata']['name']} already exists")
                return self.update_scc(scc_manifest)
            else:
                logger.error(f"Failed to create SCC: {str(e)}")
                return False
        except Exception as e:
            logger.error(f"Error creating SCC: {str(e)}")
            return False
    
    def update_scc(self, scc_manifest: Dict[str, Any]) -> bool:
        """
        Update an existing Security Context Constraint
        
        Args:
            scc_manifest: SCC manifest as dictionary
            
        Returns:
            bool: True if update successful
        """
        if not self.connected:
            logger.error("Not connected to cluster")
            return False
        
        try:
            # Get SCC resource
            scc_resource = self.dynamic_client.resources.get(
                api_version="security.openshift.io/v1",
                kind="SecurityContextConstraints"
            )
            
            scc_name = scc_manifest['metadata']['name']
            
            # Get existing SCC
            existing_scc = scc_resource.get(name=scc_name)
            
            # Update with new manifest
            scc_manifest['metadata']['resourceVersion'] = existing_scc.metadata.resourceVersion
            result = scc_resource.replace(body=scc_manifest)
            
            logger.info(f"Updated SCC: {result.metadata.name}")
            return True
            
        except ResourceNotFoundError:
            logger.info(f"SCC {scc_name} not found, creating new one")
            return self.create_scc(scc_manifest)
        except Exception as e:
            logger.error(f"Error updating SCC: {str(e)}")
            return False
    
    def delete_scc(self, scc_name: str) -> bool:
        """
        Delete a Security Context Constraint
        
        Args:
            scc_name: Name of the SCC to delete
            
        Returns:
            bool: True if deletion successful
        """
        if not self.connected:
            logger.error("Not connected to cluster")
            return False
        
        try:
            # Get SCC resource
            scc_resource = self.dynamic_client.resources.get(
                api_version="security.openshift.io/v1",
                kind="SecurityContextConstraints"
            )
            
            scc_resource.delete(name=scc_name)
            logger.info(f"Deleted SCC: {scc_name}")
            return True
            
        except ResourceNotFoundError:
            logger.info(f"SCC {scc_name} not found")
            return True
        except Exception as e:
            logger.error(f"Error deleting SCC: {str(e)}")
            return False
    
    def get_scc(self, scc_name: str) -> Optional[Dict[str, Any]]:
        """
        Get a Security Context Constraint
        
        Args:
            scc_name: Name of the SCC
            
        Returns:
            Optional[Dict]: SCC manifest or None if not found
        """
        if not self.connected:
            logger.error("Not connected to cluster")
            return None
        
        try:
            # Get SCC resource
            scc_resource = self.dynamic_client.resources.get(
                api_version="security.openshift.io/v1",
                kind="SecurityContextConstraints"
            )
            
            scc = scc_resource.get(name=scc_name)
            return scc.to_dict()
            
        except ResourceNotFoundError:
            logger.info(f"SCC {scc_name} not found")
            return None
        except Exception as e:
            logger.error(f"Error getting SCC: {str(e)}")
            return None
    
    def list_sccs(self) -> List[Dict[str, Any]]:
        """
        List all Security Context Constraints
        
        Returns:
            List[Dict]: List of SCC manifests
        """
        if not self.connected:
            logger.error("Not connected to cluster")
            return []
        
        try:
            # Get SCC resource
            scc_resource = self.dynamic_client.resources.get(
                api_version="security.openshift.io/v1",
                kind="SecurityContextConstraints"
            )
            
            sccs = scc_resource.get()
            return [scc.to_dict() for scc in sccs.items]
            
        except Exception as e:
            logger.error(f"Error listing SCCs: {str(e)}")
            return []
    
    def create_rolebinding(self, rolebinding_manifest: Dict[str, Any]) -> bool:
        """
        Create a RoleBinding
        
        Args:
            rolebinding_manifest: RoleBinding manifest as dictionary
            
        Returns:
            bool: True if creation successful
        """
        if not self.connected:
            logger.error("Not connected to cluster")
            return False
        
        try:
            # Get RoleBinding resource
            rb_resource = self.dynamic_client.resources.get(
                api_version="rbac.authorization.k8s.io/v1",
                kind="RoleBinding"
            )
            
            result = rb_resource.create(
                body=rolebinding_manifest,
                namespace=rolebinding_manifest['metadata']['namespace']
            )
            logger.info(f"Created RoleBinding: {result.metadata.name}")
            return True
            
        except ApiException as e:
            if e.status == 409:  # Already exists
                logger.info(f"RoleBinding {rolebinding_manifest['metadata']['name']} already exists")
                return True
            else:
                logger.error(f"Failed to create RoleBinding: {str(e)}")
                return False
        except Exception as e:
            logger.error(f"Error creating RoleBinding: {str(e)}")
            return False
    
    def create_clusterrolebinding(self, clusterrolebinding_manifest: Dict[str, Any]) -> bool:
        """
        Create a ClusterRoleBinding
        
        Args:
            clusterrolebinding_manifest: ClusterRoleBinding manifest as dictionary
            
        Returns:
            bool: True if creation successful
        """
        if not self.connected:
            logger.error("Not connected to cluster")
            return False
        
        try:
            # Get ClusterRoleBinding resource
            crb_resource = self.dynamic_client.resources.get(
                api_version="rbac.authorization.k8s.io/v1",
                kind="ClusterRoleBinding"
            )
            
            result = crb_resource.create(body=clusterrolebinding_manifest)
            logger.info(f"Created ClusterRoleBinding: {result.metadata.name}")
            return True
            
        except ApiException as e:
            if e.status == 409:  # Already exists
                logger.info(f"ClusterRoleBinding {clusterrolebinding_manifest['metadata']['name']} already exists")
                return True
            else:
                logger.error(f"Failed to create ClusterRoleBinding: {str(e)}")
                return False
        except Exception as e:
            logger.error(f"Error creating ClusterRoleBinding: {str(e)}")
            return False
    
    def deploy_manifest(self, manifest: Dict[str, Any], namespace: str = None) -> DeploymentResult:
        """
        Deploy a single manifest to the cluster
        
        Args:
            manifest: Kubernetes manifest as dictionary
            namespace: Target namespace (overrides manifest namespace)
            
        Returns:
            DeploymentResult: Result of deployment
        """
        if not self.connected:
            return DeploymentResult(
                success=False,
                resource_name="unknown",
                resource_kind="unknown",
                namespace=namespace or "default",
                error_message="Not connected to cluster"
            )
        
        try:
            kind = manifest.get('kind', 'Unknown')
            metadata = manifest.get('metadata', {})
            name = metadata.get('name', 'unknown')
            target_namespace = namespace or metadata.get('namespace', 'default')
            
            # Update namespace if provided
            if namespace:
                manifest['metadata']['namespace'] = namespace
            
            # Get resource
            api_version = manifest.get('apiVersion', 'v1')
            resource = self.dynamic_client.resources.get(
                api_version=api_version,
                kind=kind
            )
            
            # Deploy resource
            if hasattr(resource, 'create'):
                if kind in ['Namespace', 'ClusterRole', 'ClusterRoleBinding', 'SecurityContextConstraints']:
                    result = resource.create(body=manifest)
                else:
                    result = resource.create(body=manifest, namespace=target_namespace)
            else:
                return DeploymentResult(
                    success=False,
                    resource_name=name,
                    resource_kind=kind,
                    namespace=target_namespace,
                    error_message=f"Resource {kind} does not support create operation"
                )
            
            logger.info(f"Deployed {kind}/{name} to namespace {target_namespace}")
            return DeploymentResult(
                success=True,
                resource_name=name,
                resource_kind=kind,
                namespace=target_namespace
            )
            
        except ApiException as e:
            error_msg = f"API Error: {str(e)}"
            scc_issues = self._extract_scc_issues(str(e))
            
            logger.error(f"Failed to deploy {kind}/{name}: {error_msg}")
            return DeploymentResult(
                success=False,
                resource_name=name,
                resource_kind=kind,
                namespace=target_namespace,
                error_message=error_msg,
                scc_issues=scc_issues
            )
        except Exception as e:
            error_msg = f"Deployment error: {str(e)}"
            logger.error(f"Failed to deploy {kind}/{name}: {error_msg}")
            return DeploymentResult(
                success=False,
                resource_name=name,
                resource_kind=kind,
                namespace=target_namespace,
                error_message=error_msg
            )
    
    def deploy_manifests(self, manifests: List[Dict[str, Any]], namespace: str = None) -> List[DeploymentResult]:
        """
        Deploy multiple manifests to the cluster
        
        Args:
            manifests: List of Kubernetes manifests
            namespace: Target namespace (overrides manifest namespaces)
            
        Returns:
            List[DeploymentResult]: Results of deployments
        """
        results = []
        
        # Sort manifests by deployment order
        sorted_manifests = self._sort_manifests_by_order(manifests)
        
        for manifest in sorted_manifests:
            result = self.deploy_manifest(manifest, namespace)
            results.append(result)
            
            # If deployment fails, continue with next manifest
            if not result.success:
                logger.warning(f"Deployment failed for {result.resource_kind}/{result.resource_name}, continuing with next manifest")
        
        return results
    
    def test_manifest_deployment(self, manifest: Dict[str, Any], namespace: str = None) -> DeploymentResult:
        """
        Test deployment of a manifest without actually deploying it
        
        Args:
            manifest: Kubernetes manifest as dictionary
            namespace: Target namespace
            
        Returns:
            DeploymentResult: Result of dry-run deployment
        """
        if not self.connected:
            return DeploymentResult(
                success=False,
                resource_name="unknown",
                resource_kind="unknown",
                namespace=namespace or "default",
                error_message="Not connected to cluster"
            )
        
        try:
            kind = manifest.get('kind', 'Unknown')
            metadata = manifest.get('metadata', {})
            name = metadata.get('name', 'unknown')
            target_namespace = namespace or metadata.get('namespace', 'default')
            
            # Update namespace if provided
            if namespace:
                manifest['metadata']['namespace'] = namespace
            
            # Get resource
            api_version = manifest.get('apiVersion', 'v1')
            resource = self.dynamic_client.resources.get(
                api_version=api_version,
                kind=kind
            )
            
            # Test deployment with dry-run
            if hasattr(resource, 'create'):
                if kind in ['Namespace', 'ClusterRole', 'ClusterRoleBinding', 'SecurityContextConstraints']:
                    result = resource.create(body=manifest, dry_run='All')
                else:
                    result = resource.create(body=manifest, namespace=target_namespace, dry_run='All')
            else:
                return DeploymentResult(
                    success=False,
                    resource_name=name,
                    resource_kind=kind,
                    namespace=target_namespace,
                    error_message=f"Resource {kind} does not support create operation"
                )
            
            logger.info(f"Dry-run successful for {kind}/{name}")
            return DeploymentResult(
                success=True,
                resource_name=name,
                resource_kind=kind,
                namespace=target_namespace
            )
            
        except ApiException as e:
            error_msg = f"API Error: {str(e)}"
            scc_issues = self._extract_scc_issues(str(e))
            
            logger.error(f"Dry-run failed for {kind}/{name}: {error_msg}")
            return DeploymentResult(
                success=False,
                resource_name=name,
                resource_kind=kind,
                namespace=target_namespace,
                error_message=error_msg,
                scc_issues=scc_issues
            )
        except Exception as e:
            error_msg = f"Dry-run error: {str(e)}"
            logger.error(f"Dry-run failed for {kind}/{name}: {error_msg}")
            return DeploymentResult(
                success=False,
                resource_name=name,
                resource_kind=kind,
                namespace=target_namespace,
                error_message=error_msg
            )
    
    def get_pod_status(self, pod_name: str, namespace: str) -> Optional[Dict[str, Any]]:
        """
        Get status of a pod
        
        Args:
            pod_name: Name of the pod
            namespace: Namespace of the pod
            
        Returns:
            Optional[Dict]: Pod status or None if not found
        """
        if not self.connected:
            return None
        
        try:
            v1 = client.CoreV1Api(self.k8s_client)
            pod = v1.read_namespaced_pod(name=pod_name, namespace=namespace)
            return pod.to_dict()
            
        except ApiException as e:
            if e.status == 404:
                return None
            logger.error(f"Error getting pod status: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error getting pod status: {str(e)}")
            return None
    
    def get_pod_logs(self, pod_name: str, namespace: str) -> Optional[str]:
        """
        Get logs from a pod
        
        Args:
            pod_name: Name of the pod
            namespace: Namespace of the pod
            
        Returns:
            Optional[str]: Pod logs or None if not found
        """
        if not self.connected:
            return None
        
        try:
            v1 = client.CoreV1Api(self.k8s_client)
            logs = v1.read_namespaced_pod_log(name=pod_name, namespace=namespace)
            return logs
            
        except ApiException as e:
            if e.status == 404:
                return None
            logger.error(f"Error getting pod logs: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error getting pod logs: {str(e)}")
            return None
    
    def wait_for_pod_ready(self, pod_name: str, namespace: str, timeout: int = 300) -> bool:
        """
        Wait for a pod to be ready
        
        Args:
            pod_name: Name of the pod
            namespace: Namespace of the pod
            timeout: Timeout in seconds
            
        Returns:
            bool: True if pod becomes ready
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            pod_status = self.get_pod_status(pod_name, namespace)
            if pod_status:
                conditions = pod_status.get('status', {}).get('conditions', [])
                for condition in conditions:
                    if condition.get('type') == 'Ready' and condition.get('status') == 'True':
                        return True
            
            time.sleep(5)
        
        return False
    
    def _extract_scc_issues(self, error_message: str) -> List[str]:
        """
        Extract SCC-related issues from error messages
        
        Args:
            error_message: Error message to analyze
            
        Returns:
            List[str]: List of SCC issues found
        """
        scc_issues = []
        
        # Common SCC error patterns
        scc_patterns = [
            "unable to validate against any security context constraint",
            "unable to validate against any pod security policy",
            "pods.*forbidden.*securitycontextconstraints",
            "securitycontextconstraints.*not allowed",
            "runAsUser.*not allowed",
            "runAsGroup.*not allowed",
            "privileged.*not allowed",
            "hostNetwork.*not allowed",
            "hostPID.*not allowed",
            "hostIPC.*not allowed",
            "capabilities.*not allowed",
            "volume.*not allowed"
        ]
        
        import re
        for pattern in scc_patterns:
            if re.search(pattern, error_message, re.IGNORECASE):
                scc_issues.append(pattern)
        
        return scc_issues
    
    def _sort_manifests_by_order(self, manifests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sort manifests by deployment order
        
        Args:
            manifests: List of manifests to sort
            
        Returns:
            List[Dict]: Sorted manifests
        """
        # Define deployment order priorities
        order_priority = {
            'Namespace': 0,
            'SecurityContextConstraints': 1,
            'ServiceAccount': 2,
            'Secret': 3,
            'ConfigMap': 4,
            'PersistentVolumeClaim': 5,
            'Role': 6,
            'ClusterRole': 7,
            'RoleBinding': 8,
            'ClusterRoleBinding': 9,
            'Service': 10,
            'Deployment': 11,
            'StatefulSet': 12,
            'DaemonSet': 13,
            'Job': 14,
            'CronJob': 15,
            'Pod': 16,
            'Route': 17,
            'Ingress': 18
        }
        
        def get_priority(manifest):
            kind = manifest.get('kind', 'Unknown')
            return order_priority.get(kind, 100)
        
        return sorted(manifests, key=get_priority) 