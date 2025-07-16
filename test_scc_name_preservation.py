#!/usr/bin/env python3
"""
Test script to verify that SCC name preservation works correctly
when updating existing SCCs, even when a different name is provided
"""

import os
import sys
sys.path.insert(0, 'src')

from src.yaml_parser.manifest_parser import ManifestParser
from src.scc_manager.scc_generator import SCCGenerator

def test_scc_name_preservation():
    """Test that original SCC name is preserved when updating"""
    
    print("🔍 Testing SCC Name Preservation During Updates")
    print("=" * 60)
    
    # Initialize components
    parser = ManifestParser()
    scc_generator = SCCGenerator()
    
    # Parse the original manifest
    print("\n1️⃣ Parsing original manifest...")
    analysis = parser.parse_file("examples/deployment-with-scc.yaml")
    print(f"   Requirements: {len(analysis.security_requirements)}")
    
    # Generate initial SCC with original name
    print("\n2️⃣ Generating initial SCC with original name...")
    original_scc_name = "original-scc-name"
    initial_scc = scc_generator.generate_scc_from_requirements(analysis, original_scc_name)
    print(f"   Initial SCC name: {initial_scc['metadata']['name']}")
    
    # Parse updated manifest
    print("\n3️⃣ Parsing updated manifest...")
    updated_analysis = parser.parse_file("examples/deployment-with-scc-updated.yaml")
    print(f"   Updated requirements: {len(updated_analysis.security_requirements)}")
    
    # Test scenario: User provides a different SCC name but existing SCC should be updated
    print("\n4️⃣ Testing update with different provided name...")
    different_scc_name = "different-scc-name"
    print(f"   User provided name: {different_scc_name}")
    print(f"   Existing SCC name: {initial_scc['metadata']['name']}")
    
    # Update existing SCC (should preserve original name)
    updated_scc = scc_generator.update_existing_scc_with_requirements(initial_scc, updated_analysis)
    final_scc_name = updated_scc['metadata']['name']
    
    print(f"\n5️⃣ Results:")
    print(f"   Original SCC name: {original_scc_name}")
    print(f"   User provided name: {different_scc_name}")
    print(f"   Final SCC name: {final_scc_name}")
    
    # Verify name preservation
    if final_scc_name == original_scc_name:
        print("   ✅ SUCCESS: Original SCC name preserved!")
    else:
        print(f"   ❌ FAILED: SCC name changed from '{original_scc_name}' to '{final_scc_name}'")
    
    # Test the complete generate_or_update_scc flow
    print("\n6️⃣ Testing complete flow with mock client...")
    
    # Create a mock client that returns our existing SCC
    class MockOpenShiftClient:
        def find_existing_scc_for_service_accounts(self, service_accounts):
            return initial_scc
    
    mock_client = MockOpenShiftClient()
    
    # This should find the existing SCC and update it, preserving the original name
    result_scc = scc_generator.generate_or_update_scc(
        updated_analysis, 
        scc_name=different_scc_name,  # User provides different name
        openshift_client=mock_client
    )
    
    final_result_name = result_scc['metadata']['name']
    print(f"   Complete flow result: {final_result_name}")
    
    if final_result_name == original_scc_name:
        print("   ✅ SUCCESS: Complete flow preserves original name!")
    else:
        print(f"   ❌ FAILED: Complete flow changed name to '{final_result_name}'")
    
    print("\n" + "=" * 60)
    print("📋 Summary:")
    print(f"   - Original SCC name should be preserved during updates")
    print(f"   - User-provided names should be ignored when updating existing SCCs")
    print(f"   - Only use user-provided names when creating new SCCs")
    print("=" * 60)

if __name__ == "__main__":
    test_scc_name_preservation() 