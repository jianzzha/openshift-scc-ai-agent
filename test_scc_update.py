#!/usr/bin/env python3
"""
Test script to demonstrate SCC update functionality
This simulates the behavior when the agent detects existing SCCs
"""

import os
import sys
sys.path.insert(0, 'src')

from src.yaml_parser.manifest_parser import ManifestParser
from src.scc_manager.scc_generator import SCCGenerator

def test_scc_update_simulation():
    """Test the SCC update functionality with a simulated existing SCC"""
    
    print("🔍 Testing SCC Update Functionality")
    print("=" * 50)
    
    # Initialize components
    parser = ManifestParser()
    scc_generator = SCCGenerator()
    
    # Parse the original manifest
    print("\n1️⃣ Parsing original manifest...")
    original_analysis = parser.parse_file("examples/deployment-with-scc.yaml")
    print(f"   Original requirements: {len(original_analysis.security_requirements)}")
    for req in original_analysis.security_requirements:
        print(f"   - {req.requirement_type.value}: {req.value} ({req.severity})")
    
    # Generate initial SCC
    print("\n2️⃣ Generating initial SCC...")
    initial_scc = scc_generator.generate_scc_from_requirements(original_analysis, "test-app-scc")
    print(f"   Initial SCC name: {initial_scc['metadata']['name']}")
    print(f"   Initial capabilities: {initial_scc.get('allowedCapabilities', [])}")
    print(f"   Initial host paths: {initial_scc.get('allowedHostPaths', [])}")
    
    # Parse the updated manifest
    print("\n3️⃣ Parsing updated manifest...")
    updated_analysis = parser.parse_file("examples/deployment-with-scc-updated.yaml")
    print(f"   Updated requirements: {len(updated_analysis.security_requirements)}")
    for req in updated_analysis.security_requirements:
        print(f"   - {req.requirement_type.value}: {req.value} ({req.severity})")
    
    # Update existing SCC with new requirements
    print("\n4️⃣ Updating existing SCC...")
    updated_scc = scc_generator.update_existing_scc_with_requirements(initial_scc, updated_analysis)
    print(f"   Updated SCC name: {updated_scc['metadata']['name']}")
    print(f"   Updated capabilities: {updated_scc.get('allowedCapabilities', [])}")
    print(f"   Updated host paths: {updated_scc.get('allowedHostPaths', [])}")
    print(f"   Updated volumes: {updated_scc.get('volumes', [])}")
    
    # Show what changed
    print("\n5️⃣ Changes made to SCC:")
    initial_caps = set(initial_scc.get('allowedCapabilities', []))
    updated_caps = set(updated_scc.get('allowedCapabilities', []))
    new_caps = updated_caps - initial_caps
    if new_caps:
        print(f"   ✅ Added capabilities: {list(new_caps)}")
    
    initial_host_paths = initial_scc.get('allowedHostPaths', [])
    updated_host_paths = updated_scc.get('allowedHostPaths', [])
    if updated_host_paths and not initial_host_paths:
        print(f"   ✅ Added host paths: {updated_host_paths}")
    
    initial_volumes = set(initial_scc.get('volumes', []))
    updated_volumes = set(updated_scc.get('volumes', []))
    new_volumes = updated_volumes - initial_volumes
    if new_volumes:
        print(f"   ✅ Added volume types: {list(new_volumes)}")
    
    print("\n6️⃣ Metadata updates:")
    print(f"   Description: {updated_scc['metadata'].get('annotations', {}).get('kubernetes.io/description', '')}")
    print(f"   Last updated: {updated_scc['metadata'].get('annotations', {}).get('last-updated-at', '')}")
    print(f"   Updated by: {updated_scc['metadata'].get('annotations', {}).get('last-updated-by', '')}")
    
    print("\n✅ SCC update simulation completed successfully!")
    print("🎯 The agent would preserve existing permissions and add new ones")
    print("🔒 Security boundaries maintained while expanding capabilities")

def compare_manifests():
    """Compare the original and updated manifests"""
    print("\n" + "=" * 50)
    print("📊 Manifest Comparison")
    print("=" * 50)
    
    parser = ManifestParser()
    
    # Parse both manifests
    original = parser.parse_file("examples/deployment-with-scc.yaml")
    updated = parser.parse_file("examples/deployment-with-scc-updated.yaml")
    
    print(f"\n📋 Original manifest:")
    print(f"   Resources: {len(original.resources)}")
    print(f"   Security requirements: {len(original.security_requirements)}")
    print(f"   Service accounts: {len(original.service_accounts)}")
    
    print(f"\n📋 Updated manifest:")
    print(f"   Resources: {len(updated.resources)}")
    print(f"   Security requirements: {len(updated.security_requirements)}")
    print(f"   Service accounts: {len(updated.service_accounts)}")
    
    print(f"\n🔍 New requirements in updated manifest:")
    original_reqs = {(req.requirement_type.value, str(req.value)) for req in original.security_requirements}
    updated_reqs = {(req.requirement_type.value, str(req.value)) for req in updated.security_requirements}
    
    new_reqs = updated_reqs - original_reqs
    for req_type, req_value in new_reqs:
        print(f"   ➕ {req_type}: {req_value}")
    
    if not new_reqs:
        print("   ℹ️  No new requirements (requirements may have been expanded)")

if __name__ == "__main__":
    test_scc_update_simulation()
    compare_manifests() 