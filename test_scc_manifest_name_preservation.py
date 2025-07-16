#!/usr/bin/env python3
"""
Test script to verify that SCC names, ClusterRole names, and RoleBinding names 
are preserved from the manifest when no -n flag is provided
"""

import os
import sys
sys.path.insert(0, 'src')

from src.yaml_parser.manifest_parser import ManifestParser
from src.scc_manager.scc_generator import SCCGenerator

def test_manifest_name_preservation():
    """Test that names from manifest are preserved when no -n flag is provided"""
    
    print("🔍 Testing Manifest Name Preservation")
    print("=" * 60)
    
    # Initialize components
    parser = ManifestParser()
    scc_generator = SCCGenerator()
    
    # Test with deployment-with-scc.yaml
    print("\n1️⃣ Testing with deployment-with-scc.yaml...")
    manifest_path = "examples/deployment-with-scc.yaml"
    
    # Extract existing RBAC resources
    rbac_resources = parser.extract_existing_rbac_resources(manifest_path)
    print(f"   Existing SCC: {rbac_resources['scc']['name'] if rbac_resources['scc'] else 'None'}")
    print(f"   Existing ClusterRoles: {[cr['name'] for cr in rbac_resources['cluster_roles']]}")
    print(f"   Existing RoleBindings: {[rb['name'] for rb in rbac_resources['role_bindings']]}")
    
    # Parse manifest for analysis
    analysis = parser.parse_file(manifest_path)
    print(f"   Service accounts: {[sa.name for sa in analysis.service_accounts]}")
    
    # Test scenario 1: No -n flag provided (should use manifest SCC name)
    print("\n2️⃣ Testing without -n flag (should use manifest SCC name)...")
    
    # Create a mock OpenShift client that returns no existing SCCs
    class MockOpenShiftClient:
        def find_existing_scc_for_service_accounts(self, service_accounts):
            return None
    
    mock_client = MockOpenShiftClient()
    
    # Generate SCC without providing scc_name (should use manifest name)
    result_scc = scc_generator.generate_or_update_scc(
        analysis, 
        scc_name=None,  # No -n flag provided
        openshift_client=mock_client,
        force_new=False
    )
    
    result_name = result_scc['metadata']['name']
    expected_name = rbac_resources['scc']['name']
    
    print(f"   Expected SCC name: {expected_name}")
    print(f"   Result SCC name: {result_name}")
    
    if result_name == expected_name:
        print("   ✅ SUCCESS: SCC name preserved from manifest!")
    else:
        print(f"   ❌ FAILED: Expected '{expected_name}', got '{result_name}'")
    
    # Test scenario 2: -n flag provided (should override manifest name)
    print("\n3️⃣ Testing with -n flag (should override manifest name)...")
    
    override_name = "user-provided-scc"
    result_scc_override = scc_generator.generate_or_update_scc(
        analysis, 
        scc_name=override_name,  # -n flag provided
        openshift_client=mock_client,
        force_new=False
    )
    
    result_name_override = result_scc_override['metadata']['name']
    
    print(f"   User provided name: {override_name}")
    print(f"   Result SCC name: {result_name_override}")
    
    if result_name_override == override_name:
        print("   ✅ SUCCESS: User-provided name used!")
    else:
        print(f"   ❌ FAILED: Expected '{override_name}', got '{result_name_override}'")
    
    # Test scenario 3: force_new flag (should use provided or generate new name)
    print("\n4️⃣ Testing with force_new flag...")
    
    result_scc_force = scc_generator.generate_or_update_scc(
        analysis, 
        scc_name=None,  # No name provided
        openshift_client=mock_client,
        force_new=True
    )
    
    result_name_force = result_scc_force['metadata']['name']
    
    print(f"   Force new SCC name: {result_name_force}")
    print(f"   Should be auto-generated: {result_name_force.startswith('generated-')}")
    
    if result_name_force.startswith('generated-'):
        print("   ✅ SUCCESS: New name generated with force_new!")
    else:
        print(f"   ❌ FAILED: Expected auto-generated name, got '{result_name_force}'")
    
    # Test RBAC resource name preservation
    print("\n5️⃣ Testing RBAC resource name preservation...")
    
    rbac_resources_result = scc_generator.create_rbac_resources_from_manifest(
        analysis, 
        rbac_resources['scc']['name']
    )
    
    cluster_role_result = rbac_resources_result['cluster_role']
    role_bindings_result = rbac_resources_result['role_bindings']
    
    print(f"   Generated ClusterRole name: {cluster_role_result['metadata']['name']}")
    print(f"   Generated RoleBinding names: {[rb['metadata']['name'] for rb in role_bindings_result]}")
    
    # Check if names match existing names from manifest
    expected_cluster_role_name = rbac_resources['cluster_roles'][0]['name'] if rbac_resources['cluster_roles'] else f"system:openshift:scc:{rbac_resources['scc']['name']}"
    expected_role_binding_names = [rb['name'] for rb in rbac_resources['role_bindings']]
    
    cluster_role_match = cluster_role_result['metadata']['name'] == expected_cluster_role_name
    role_binding_match = all(rb['metadata']['name'] in expected_role_binding_names for rb in role_bindings_result)
    
    print(f"   ClusterRole name match: {'✅' if cluster_role_match else '❌'}")
    print(f"   RoleBinding name match: {'✅' if role_binding_match else '❌'}")
    
    print("\n" + "=" * 60)
    print("📋 Summary of Name Preservation Logic:")
    print("   1. If -n flag provided: Use user-provided name")
    print("   2. If manifest has SCC and no -n flag: Use manifest SCC name")
    print("   3. If force_new=True: Generate new name")
    print("   4. If no manifest SCC and no -n flag: Generate new name")
    print("   5. Always preserve existing ClusterRole and RoleBinding names")
    print("=" * 60)

def test_different_manifests():
    """Test name preservation with different manifest files"""
    print("\n🔍 Testing Different Manifest Files")
    print("=" * 50)
    
    parser = ManifestParser()
    
    # Test files with existing SCCs
    scc_files = [
        "examples/deployment-with-scc.yaml",
        "examples/deployment-with-scc-updated.yaml", 
        "examples/deployment-with-sufficient-scc.yaml"
    ]
    
    for file_path in scc_files:
        print(f"\n📄 Testing {file_path}...")
        
        rbac_resources = parser.extract_existing_rbac_resources(file_path)
        if rbac_resources['scc']:
            print(f"   SCC name: {rbac_resources['scc']['name']}")
        else:
            print("   No SCC found in manifest")
        
        print(f"   ClusterRoles: {len(rbac_resources['cluster_roles'])}")
        print(f"   RoleBindings: {len(rbac_resources['role_bindings'])}")
        print(f"   ClusterRoleBindings: {len(rbac_resources['cluster_role_bindings'])}")
    
    # Test files without existing SCCs
    print(f"\n📄 Testing files without SCCs...")
    no_scc_files = [
        "examples/nginx-deployment.yaml",
        "examples/database-app.yaml", 
        "examples/privileged-app.yaml"
    ]
    
    for file_path in no_scc_files:
        print(f"\n   {file_path}:")
        try:
            rbac_resources = parser.extract_existing_rbac_resources(file_path)
            has_scc = rbac_resources['scc'] is not None
            print(f"     Has SCC: {has_scc}")
            
            if not has_scc:
                analysis = parser.parse_file(file_path)
                print(f"     Service accounts: {[sa.name for sa in analysis.service_accounts]}")
        except Exception as e:
            print(f"     Error: {e}")

if __name__ == "__main__":
    test_manifest_name_preservation()
    test_different_manifests() 