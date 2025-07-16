#!/usr/bin/env python3
"""
Example: Using OpenShift SCC AI Agent programmatically
This demonstrates how an agent orchestrator can integrate with the SCC AI Agent.
"""

import sys
import os
sys.path.insert(0, 'src')

from src.yaml_parser.manifest_parser import ManifestParser
from src.scc_manager.scc_generator import SCCGenerator
from src.openshift_client.client import OpenShiftClient
from src.ai_agent.scc_ai_agent import SCCAIAgent, AIProvider
from typing import Dict, Any, List, Optional

class SCCAgentOrchestrator:
    """
    Agent orchestrator interface for OpenShift SCC AI Agent
    """
    
    def __init__(self, kubeconfig_path: Optional[str] = None, ai_provider: str = "openai", api_key: Optional[str] = None):
        """Initialize the orchestrator"""
        self.manifest_parser = ManifestParser()
        self.scc_generator = SCCGenerator()
        self.openshift_client = OpenShiftClient(kubeconfig_path)
        self.ai_agent = SCCAIAgent(AIProvider(ai_provider), api_key)
        
    def connect_to_cluster(self) -> bool:
        """Connect to OpenShift cluster"""
        return self.openshift_client.connect()
    
    def analyze_manifests(self, manifest_path: str) -> Dict[str, Any]:
        """
        Analyze YAML manifests and extract security requirements
        
        Args:
            manifest_path: Path to manifest file or directory
            
        Returns:
            Dict: Analysis results with security requirements
        """
        if os.path.isfile(manifest_path):
            analysis = self.manifest_parser.parse_file(manifest_path)
        else:
            analyses = self.manifest_parser.parse_directory(manifest_path)
            analysis = self.manifest_parser.combine_analyses(analyses)
        
        return self.manifest_parser.get_analysis_summary(analysis)
    
    def generate_scc(self, manifest_path: str, scc_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate or update SCC from manifest analysis
        
        Args:
            manifest_path: Path to manifest file
            scc_name: Name for the generated SCC (optional)
            
        Returns:
            Dict: Generated or updated SCC manifest
        """
        analysis = self.manifest_parser.parse_file(manifest_path)
        scc_manifest = self.scc_generator.generate_or_update_scc(analysis, scc_name, self.openshift_client)
        return scc_manifest
    
    def deploy_with_ai_assistance(self, manifest_path: str, scc_name: Optional[str] = None, max_iterations: int = 3) -> Dict[str, Any]:
        """
        Deploy manifests with AI-powered SCC adjustment
        
        Args:
            manifest_path: Path to manifest file
            scc_name: Name for SCC (auto-generated if not provided)
            max_iterations: Maximum AI adjustment iterations
            
        Returns:
            Dict: Deployment results
        """
        # Parse manifests
        analysis = self.manifest_parser.parse_file(manifest_path)
        
        # Generate SCC name if not provided
        if not scc_name:
            scc_name = f"ai-generated-{hash(manifest_path) % 10000}"
        
        # Generate initial SCC
        scc_manifest = self.scc_generator.generate_scc_from_requirements(analysis, scc_name)
        
        # Deploy SCC and RBAC
        results = {
            "scc_created": self.openshift_client.create_scc(scc_manifest),
            "clusterrole_created": False,
            "rolebindings_created": [],
            "manifests_deployed": [],
            "ai_iterations": 0,
            "success": False
        }
        
        # Create ClusterRole
        clusterrole = self.scc_generator.create_clusterrole(scc_name)
        results["clusterrole_created"] = self.openshift_client.create_clusterrole(clusterrole)
        
        # Create role bindings
        for sa in analysis.service_accounts:
            rolebinding = self.scc_generator.create_rolebinding(scc_name, sa.name, sa.namespace)
            success = self.openshift_client.create_rolebinding(rolebinding)
            results["rolebindings_created"].append({"service_account": sa.name, "success": success})
        
        # Iterative deployment with AI
        current_scc = scc_manifest
        for iteration in range(max_iterations):
            results["ai_iterations"] = iteration + 1
            
            # Try to deploy manifests
            deployment_results = []
            for resource in analysis.resources:
                result = self.openshift_client.deploy_manifest(resource)
                deployment_results.append(result)
            
            results["manifests_deployed"] = deployment_results
            
            # Check for failures
            failures = [r for r in deployment_results if not r.success]
            if not failures:
                results["success"] = True
                break
            
            # Focus on SCC-related failures
            scc_failures = [r for r in failures if r.scc_issues]
            if not scc_failures:
                break
            
            # Use AI to analyze and adjust
            ai_analysis = self.ai_agent.analyze_deployment_failure(
                scc_failures[0], current_scc, analysis
            )
            
            if ai_analysis.success and ai_analysis.suggested_adjustments:
                adjusted_scc = self.ai_agent.apply_ai_adjustments(current_scc, ai_analysis)
                if self.openshift_client.update_scc(adjusted_scc):
                    current_scc = adjusted_scc
                else:
                    break
            else:
                break
        
        return results
    
    def get_cluster_sccs(self) -> List[Dict[str, Any]]:
        """Get all SCCs from the cluster"""
        return self.openshift_client.list_sccs()
    
    def cleanup_resources(self, scc_name: str, namespace: Optional[str] = None) -> Dict[str, bool]:
        """
        Clean up created resources
        
        Args:
            scc_name: Name of SCC to clean up
            namespace: Namespace for role bindings
            
        Returns:
            Dict: Cleanup results
        """
        return {
            "scc_deleted": self.openshift_client.delete_scc(scc_name),
            # Note: delete_clusterrole method not implemented in OpenShiftClient yet
            "clusterrole_deleted": False,  # Would need to implement delete_clusterrole method
            # Note: RoleBindings would need namespace-specific cleanup
        }

# Example usage for agent orchestrator
def main():
    """Example usage"""
    orchestrator = SCCAgentOrchestrator(
        kubeconfig_path="~/.kube/config",
        ai_provider="openai",
        api_key=os.getenv("OPENAI_API_KEY")
    )
    
    # Connect to cluster
    if not orchestrator.connect_to_cluster():
        print("Failed to connect to cluster")
        return
    
    # Analyze manifests
    analysis = orchestrator.analyze_manifests("examples/nginx-deployment.yaml")
    print(f"Security requirements found: {len(analysis.get('security_requirements', []))}")
    
    # Generate SCC
    scc_manifest = orchestrator.generate_scc("examples/nginx-deployment.yaml", "nginx-scc")
    print(f"Generated SCC: {scc_manifest['metadata']['name']}")
    
    # Deploy with AI assistance
    deployment_results = orchestrator.deploy_with_ai_assistance(
        "examples/nginx-deployment.yaml", 
        "nginx-scc",
        max_iterations=3
    )
    
    print(f"Deployment success: {deployment_results['success']}")
    print(f"AI iterations: {deployment_results['ai_iterations']}")

if __name__ == "__main__":
    main() 