#!/usr/bin/env python3
"""
Test script to demonstrate scenarios where existing SCCs already have sufficient permissions
and no updates are needed
"""

import os
import sys
sys.path.insert(0, 'src')

from src.yaml_parser.manifest_parser import ManifestParser
from src.scc_manager.scc_generator import SCCGenerator

def test_scc_no_update_needed():
    """Test scenario where existing SCC already has sufficient permissions"""
    
    print("🔍 Testing SCC with Sufficient Permissions (No Update Needed)")
    print("=" * 70)
    
    # Initialize components
    parser = ManifestParser()
    scc_generator = SCCGenerator()
    
    # Parse the manifest with sufficient SCC
    print("\n1️⃣ Parsing manifest with sufficient SCC...")
    analysis = parser.parse_file("examples/deployment-with-sufficient-scc.yaml")
    
    print(f"   Security requirements found: {len(analysis.security_requirements)}")
    for req in analysis.security_requirements:
        print(f"   - {req.requirement_type.value}: {req.value} ({req.severity})")
    
    print(f"   Service accounts: {len(analysis.service_accounts)}")
    for sa in analysis.service_accounts:
        print(f"   - {sa.name} (namespace: {sa.namespace})")
    
    # Extract the existing SCC from the manifest
    print("\n2️⃣ Extracting existing SCC from manifest...")
    existing_scc = None
    
    # Parse the YAML documents to find the SCC
    import yaml
    with open("examples/deployment-with-sufficient-scc.yaml", 'r') as f:
        docs = yaml.safe_load_all(f)
        for doc in docs:
            if doc and doc.get('kind') == 'SecurityContextConstraints':
                existing_scc = doc
                break
    
    if existing_scc:
        print(f"   Found existing SCC: {existing_scc['metadata']['name']}")
        print(f"   Existing capabilities: {existing_scc.get('allowedCapabilities', [])}")
        print(f"   Existing host paths: {existing_scc.get('allowedHostPaths', [])}")
        print(f"   Existing volume types: {existing_scc.get('volumes', [])}")
    else:
        print("   ❌ No SCC found in manifest")
        return
    
    # Test what would happen if we tried to update this SCC
    print("\n3️⃣ Testing SCC update with existing sufficient permissions...")
    updated_scc = scc_generator.update_existing_scc_with_requirements(existing_scc, analysis)
    
    print(f"   Updated SCC name: {updated_scc['metadata']['name']}")
    print(f"   Updated capabilities: {updated_scc.get('allowedCapabilities', [])}")
    print(f"   Updated host paths: {updated_scc.get('allowedHostPaths', [])}")
    print(f"   Updated volume types: {updated_scc.get('volumes', [])}")
    
    # Compare original vs updated
    print("\n4️⃣ Comparing original vs updated SCC...")
    original_caps = set(existing_scc.get('allowedCapabilities', []))
    updated_caps = set(updated_scc.get('allowedCapabilities', []))
    
    original_volumes = set(existing_scc.get('volumes', []))
    updated_volumes = set(updated_scc.get('volumes', []))
    
    original_host_paths = existing_scc.get('allowedHostPaths', [])
    updated_host_paths = updated_scc.get('allowedHostPaths', [])
    
    caps_added = updated_caps - original_caps
    volumes_added = updated_volumes - original_volumes
    host_paths_added = len(updated_host_paths) - len(original_host_paths)
    
    print(f"   Capabilities added: {list(caps_added) if caps_added else 'None'}")
    print(f"   Volume types added: {list(volumes_added) if volumes_added else 'None'}")
    print(f"   Host paths added: {host_paths_added if host_paths_added > 0 else 'None'}")
    
    # Determine if update was actually needed
    update_needed = bool(caps_added or volumes_added or host_paths_added > 0)
    
    print(f"\n5️⃣ Update assessment:")
    if update_needed:
        print("   ⚠️  Update was needed - SCC was missing some permissions")
    else:
        print("   ✅ No update needed - SCC already had sufficient permissions!")
    
    # Test the complete flow
    print("\n6️⃣ Testing complete flow with mock client...")
    
    class MockOpenShiftClient:
        def find_existing_scc_for_service_accounts(self, service_accounts):
            return existing_scc
    
    mock_client = MockOpenShiftClient()
    
    # Generate or update SCC
    result_scc = scc_generator.generate_or_update_scc(
        analysis,
        scc_name="web-app-scc",
        openshift_client=mock_client
    )
    
    print(f"   Result SCC name: {result_scc['metadata']['name']}")
    
    # Check if the result is functionally the same as the original
    result_caps = set(result_scc.get('allowedCapabilities', []))
    result_volumes = set(result_scc.get('volumes', []))
    
    same_caps = result_caps == original_caps
    same_volumes = result_volumes == original_volumes
    
    if same_caps and same_volumes:
        print("   ✅ Complete flow: No significant changes made")
    else:
        print("   ⚠️  Complete flow: Some changes were made")
    
    print("\n" + "=" * 70)
    print("📋 Summary - Deployment with Sufficient SCC:")
    print("   - Deployment needs: NET_BIND_SERVICE capability")
    print("   - SCC already has: NET_BIND_SERVICE + CHOWN + DAC_OVERRIDE + SETUID + SETGID + SYS_CHROOT")
    print("   - Deployment needs: configMap, emptyDir volumes")
    print("   - SCC already has: configMap + emptyDir + hostPath + persistentVolumeClaim + etc.")
    print("   - Result: No updates needed, existing SCC is sufficient")
    print("=" * 70)

def compare_manifests():
    """Compare all three example manifests to show progression"""
    print("\n🔍 Comparing All Example Manifests")
    print("=" * 50)
    
    parser = ManifestParser()
    
    # Parse all three manifests
    manifests = [
        ("deployment-with-scc.yaml", "Basic deployment with minimal SCC"),
        ("deployment-with-scc-updated.yaml", "Enhanced deployment requiring SCC updates"),
        ("deployment-with-sufficient-scc.yaml", "Deployment with already sufficient SCC")
    ]
    
    for filename, description in manifests:
        print(f"\n📄 {description}")
        print(f"   File: examples/{filename}")
        
        try:
            analysis = parser.parse_file(f"examples/{filename}")
            print(f"   Security requirements: {len(analysis.security_requirements)}")
            for req in analysis.security_requirements:
                print(f"   - {req.requirement_type.value}: {req.value}")
        except Exception as e:
            print(f"   ❌ Error parsing: {e}")

if __name__ == "__main__":
    test_scc_no_update_needed()
    compare_manifests() 