#!/usr/bin/env python3

import os
import sys
import click
import yaml
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.markdown import Markdown
from loguru import logger
import tempfile

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.yaml_parser.manifest_parser import ManifestParser
from src.scc_manager.scc_generator import SCCGenerator
from src.openshift_client.client import OpenShiftClient
from src.ai_agent.scc_ai_agent import SCCAIAgent, AIProvider

console = Console()

def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    log_level = "DEBUG" if verbose else "INFO"
    logger.remove()
    logger.add(sys.stderr, level=log_level, format="<green>{time}</green> | <level>{level}</level> | {message}")
    logger.add("logs/scc-ai-agent.log", rotation="1 MB", level="DEBUG")

@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
@click.pass_context
def cli(ctx, verbose, config):
    """OpenShift SCC AI Agent - Intelligent Security Context Constraints Management"""
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['config'] = config
    
    # Ensure directories exist
    os.makedirs('logs', exist_ok=True)
    os.makedirs('output', exist_ok=True)
    
    setup_logging(verbose)

@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for analysis report')
@click.option('--format', '-f', type=click.Choice(['json', 'yaml', 'table']), default='table', help='Output format')
@click.pass_context
def analyze(ctx, path, output, format):
    """Analyze YAML manifests and extract security requirements"""
    console.print(f"[bold blue]Analyzing manifests in: {path}[/bold blue]")
    
    parser = ManifestParser()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("Analyzing manifests...", total=None)
        
        if os.path.isfile(path):
            analysis = parser.parse_file(path)
        else:
            analyses = parser.parse_directory(path)
            analysis = parser.combine_analyses(analyses)
        
        progress.update(task, description="Analysis complete")
    
    # Analyze SCC status
    scc_status = _analyze_scc_status(analysis)
    
    # Display results
    if format == 'table':
        _display_analysis_table(analysis)
        _display_scc_status_table(scc_status)
    elif format == 'json':
        result = parser.get_analysis_summary(analysis)
        result['scc_status'] = scc_status
        if output:
            with open(output, 'w') as f:
                json.dump(result, f, indent=2)
        else:
            console.print(json.dumps(result, indent=2))
    elif format == 'yaml':
        result = parser.get_analysis_summary(analysis)
        result['scc_status'] = scc_status
        if output:
            with open(output, 'w') as f:
                yaml.dump(result, f, default_flow_style=False)
        else:
            console.print(yaml.dump(result, default_flow_style=False))
    
    # Show summary
    summary = parser.get_analysis_summary(analysis)
    summary['scc_status'] = scc_status
    _display_summary_panel(summary)

@cli.command()
@click.argument('manifest_path', type=click.Path(exists=True))
@click.option('--scc-name', '-n', help='Name for the generated SCC (optional - will detect existing if not provided)')
@click.option('--output', '-o', type=click.Path(), help='Output path: directory for separate files, file path for single file')
@click.option('--single-file', is_flag=True, help='Save all resources in a single multi-document YAML file (requires file path in --output)')
@click.option('--suggest-existing', '-s', is_flag=True, help='Suggest existing SCC instead of creating new one')
@click.option('--optimize', is_flag=True, help='Optimize the generated SCC')
@click.option('--update-existing', is_flag=True, help='Update existing SCC if found (default behavior)')
@click.option('--force-new', is_flag=True, help='Force creation of new SCC even if existing ones are found')
@click.option('--kubeconfig', '-k', type=click.Path(), help='Path to kubeconfig file')
@click.pass_context
def generate_scc(ctx, manifest_path, scc_name, output, suggest_existing, optimize, update_existing, force_new, kubeconfig, single_file):
    """Generate or update SCC from manifest analysis"""
    console.print(f"[bold blue]Analyzing manifests in: {manifest_path}[/bold blue]")
    
    # Parse manifests
    parser = ManifestParser()
    if os.path.isfile(manifest_path):
        analysis = parser.parse_file(manifest_path)
    else:
        analyses = parser.parse_directory(manifest_path)
        analysis = parser.combine_analyses(analyses)
    
    scc_generator = SCCGenerator()
    
    if suggest_existing:
        suggested_scc = scc_generator.suggest_existing_scc(analysis)
        console.print(f"[green]Suggested existing SCC: {suggested_scc}[/green]")
        
        if click.confirm("Would you like to see the details of this SCC?"):
            predefined_scc = scc_generator.predefined_sccs.get(suggested_scc) if suggested_scc else None
            if predefined_scc:
                console.print(Syntax(yaml.dump(predefined_scc, default_flow_style=False), "yaml"))
        return
    
    # Connect to cluster if kubeconfig provided and not forcing new SCC
    openshift_client = None
    if kubeconfig and not force_new:
        from src.openshift_client.client import OpenShiftClient
        openshift_client = OpenShiftClient(kubeconfig)
        if openshift_client.connect():
            console.print("[green]✓ Connected to OpenShift cluster[/green]")
        else:
            console.print("[yellow]⚠ Failed to connect to cluster, will generate new SCC[/yellow]")
            openshift_client = None
    
    # Check for existing SCC associations
    existing_scc_found = False
    if openshift_client and analysis.service_accounts:
        console.print("\n[bold]Checking for existing SCC associations...[/bold]")
        
        # Convert service accounts to format expected by client
        service_accounts = [
            {'name': sa.name, 'namespace': sa.namespace} 
            for sa in analysis.service_accounts
        ]
        
        # Show service accounts being checked
        for sa in analysis.service_accounts:
            scc_associations = openshift_client.get_service_account_scc_associations(sa.name, sa.namespace)
            if scc_associations:
                console.print(f"[yellow]  Service account {sa.name} in {sa.namespace} is associated with SCCs: {', '.join(scc_associations)}[/yellow]")
                existing_scc_found = True
            else:
                console.print(f"[dim]  Service account {sa.name} in {sa.namespace} has no SCC associations[/dim]")
    
    # Generate or update SCC - Handle SCC name changes properly
    console.print(f"\n[bold]Generating or updating SCC...[/bold]")
    
    # Check if user provided a custom SCC name that might require cleanup
    cleanup_info = None
    if scc_name and openshift_client:
        # Handle potential SCC name change scenario
        cleanup_info = scc_generator.handle_scc_name_change(analysis, scc_name, openshift_client)
        scc_manifest = cleanup_info["scc_manifest"]
        
        if cleanup_info["cleanup_needed"]:
            if cleanup_info["cleanup_successful"]:
                console.print(f"[green]✓ Cleaned up old RBAC resources for previous SCC: {cleanup_info['original_scc_name']}[/green]")
            else:
                console.print(f"[yellow]⚠ Some old RBAC resources for SCC {cleanup_info['original_scc_name']} could not be cleaned up[/yellow]")
    else:
        # Use standard logic for other cases
        scc_manifest = scc_generator.generate_or_update_scc(analysis, scc_name, openshift_client, force_new)
    
    operation = "updated" if existing_scc_found else "created"
    
    if optimize:
        scc_manifest = scc_generator.optimize_scc(scc_manifest, analysis)
        console.print("[green]✓ SCC optimized[/green]")
    
    # Display SCC info
    scc_name_final = scc_manifest['metadata']['name']
    console.print(f"\n[bold green]SCC {operation}: {scc_name_final}[/bold green]")
    
    # Show name change information if applicable
    if cleanup_info and cleanup_info["cleanup_needed"]:
        console.print(f"[dim]SCC name changed from '{cleanup_info['original_scc_name']}' to '{cleanup_info['new_scc_name']}'[/dim]")
    
    # Generate ClusterRole for SCC
    console.print("\n[bold]Generated ClusterRole:[/bold]")
    clusterrole = scc_generator.create_clusterrole(scc_name_final)
    console.print(Syntax(yaml.dump(clusterrole, default_flow_style=False), "yaml"))
    
    # Generate role bindings for service accounts
    console.print("\n[bold]Generated Role Bindings:[/bold]")
    rolebindings = []
    for sa in analysis.service_accounts:
        rolebinding = scc_generator.create_rolebinding(scc_name_final, sa.name, sa.namespace)
        rolebindings.append((rolebinding, sa))
        console.print(f"RoleBinding for {sa.name} in {sa.namespace}:")
        console.print(Syntax(yaml.dump(rolebinding, default_flow_style=False), "yaml"))
    
    # Output all generated resources
    if output:
        output_path = Path(output)
        
        if single_file:
            # Single file mode: expect a file path
            # Ensure parent directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Save all resources in a single multi-document YAML file
            all_resources = [scc_manifest, clusterrole]
            all_resources.extend([rb for rb, sa in rolebindings])
            
            with open(output_path, 'w') as f:
                for i, resource in enumerate(all_resources):
                    if i > 0:
                        f.write('\n---\n')
                    yaml.dump(resource, f, default_flow_style=False)
            
            console.print(f"[green]All RBAC resources saved to: {output_path}[/green]")
            console.print(f"[dim]File contains {len(all_resources)} resources: 1 SCC, 1 ClusterRole, {len(rolebindings)} RoleBinding(s)[/dim]")
        else:
            # Separate files mode: expect a directory path
            
            # If output path doesn't have a suffix and doesn't end with '/', treat it as a directory
            if not output_path.suffix and not str(output_path).endswith('/'):
                output_dir = output_path
            elif output_path.suffix:
                # If it has a suffix, treat it as a file path and use its parent as directory
                output_dir = output_path.parent
            else:
                # It ends with '/', treat as directory
                output_dir = output_path
            
            # Ensure output directory exists
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate base name for files (use SCC name)
            base_name = scc_name_final
            
            # Save SCC
            scc_file = output_dir / f"{base_name}-scc.yaml"
            with open(scc_file, 'w') as f:
                yaml.dump(scc_manifest, f, default_flow_style=False)
            console.print(f"[green]SCC saved to: {scc_file}[/green]")
            
            # Save ClusterRole
            clusterrole_file = output_dir / f"{base_name}-clusterrole.yaml"
            with open(clusterrole_file, 'w') as f:
                yaml.dump(clusterrole, f, default_flow_style=False)
            console.print(f"[green]ClusterRole saved to: {clusterrole_file}[/green]")
            
            # Save RoleBindings
            for rolebinding, sa in rolebindings:
                rolebinding_file = output_dir / f"{base_name}-rolebinding-{sa.name}-{sa.namespace}.yaml"
                with open(rolebinding_file, 'w') as f:
                    yaml.dump(rolebinding, f, default_flow_style=False)
                console.print(f"[green]RoleBinding saved to: {rolebinding_file}[/green]")
            
            # Show summary of saved files
            total_files = 2 + len(rolebindings)  # SCC + ClusterRole + RoleBindings
            console.print(f"\n[bold green]✓ {total_files} RBAC resource files saved to {output_dir}/[/bold green]")
    else:
        console.print(Syntax(yaml.dump(scc_manifest, default_flow_style=False), "yaml"))
    
    # Show what was updated if existing SCC was found
    if existing_scc_found and operation == "updated":
        console.print(f"\n[bold yellow]📝 Note:[/bold yellow] Updated existing SCC with new requirements from {manifest_path}")
        console.print("[dim]The SCC has been extended with additional permissions while preserving existing ones.[/dim]")
    
    # Offer to deploy the SCC
    if openshift_client:
        if click.confirm(f"\nWould you like to deploy the {operation} SCC and RBAC to the cluster?"):
            deploy_success = True
            
            # Deploy or update SCC
            if operation == "updated":
                success = openshift_client.update_scc(scc_manifest)
            else:
                success = openshift_client.create_scc(scc_manifest)
            
            if success:
                console.print(f"[green]✓ SCC {operation} successfully[/green]")
            else:
                console.print(f"[red]✗ Failed to {operation.replace('d', '')} SCC[/red]")
                deploy_success = False
            
            # Deploy ClusterRole
            if openshift_client.create_clusterrole(clusterrole):
                console.print("[green]✓ ClusterRole created successfully[/green]")
            else:
                console.print("[yellow]⚠ ClusterRole creation failed or already exists[/yellow]")
            
            # Deploy RoleBindings
            for sa in analysis.service_accounts:
                rolebinding = scc_generator.create_rolebinding(scc_name_final, sa.name, sa.namespace)
                if openshift_client.create_rolebinding(rolebinding):
                    console.print(f"[green]✓ RoleBinding created for {sa.name}[/green]")
                else:
                    console.print(f"[yellow]⚠ RoleBinding creation failed for {sa.name}[/yellow]")
            
            if deploy_success:
                console.print(f"\n[bold green]🎉 SCC '{scc_name_final}' and RBAC deployed successfully![/bold green]")

@cli.command()
@click.option('--kubeconfig', '-k', type=click.Path(), help='Path to kubeconfig file')
@click.option('--kubeconfig-content', type=str, help='Kubeconfig content as string')
@click.option('--test-connection', is_flag=True, help='Test connection only')
@click.pass_context
def connect(ctx, kubeconfig, kubeconfig_content, test_connection):
    """Connect to OpenShift cluster"""
    console.print("[bold blue]Connecting to OpenShift cluster...[/bold blue]")
    
    client = OpenShiftClient(kubeconfig)
    
    if kubeconfig_content:
        success = client.connect(kubeconfig_content)
    else:
        success = client.connect()
    
    if success:
        console.print("[green]✓ Successfully connected to cluster[/green]")
        if client.cluster_info:
            table = Table(title="Cluster Information")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")
            
            table.add_row("API URL", client.cluster_info.api_url)
            table.add_row("Version", client.cluster_info.version)
            table.add_row("Username", client.cluster_info.username)
            table.add_row("Namespace", client.cluster_info.namespace)
            
            console.print(table)
        
        if not test_connection:
            # Store connection info for subsequent commands
            ctx.obj['client'] = client
    else:
        console.print("[red]✗ Failed to connect to cluster[/red]")
        sys.exit(1)

@cli.command()
@click.argument('manifest_path', type=click.Path(exists=True))
@click.option('--namespace', '-n', help='Target namespace')
@click.option('--dry-run', is_flag=True, help='Perform dry-run deployment')
@click.option('--kubeconfig', '-k', type=click.Path(), help='Path to kubeconfig file')
@click.option('--wait', is_flag=True, help='Wait for deployment to complete')
@click.pass_context
def deploy(ctx, manifest_path, namespace, dry_run, kubeconfig, wait):
    """Deploy manifests to OpenShift cluster"""
    console.print(f"[bold blue]Deploying manifests from: {manifest_path}[/bold blue]")
    
    # Get or create client
    client = ctx.obj.get('client')
    if not client:
        client = OpenShiftClient(kubeconfig)
        if not client.connect():
            console.print("[red]✗ Failed to connect to cluster[/red]")
            sys.exit(1)
    
    # Parse manifests
    parser = ManifestParser()
    if os.path.isfile(manifest_path):
        analysis = parser.parse_file(manifest_path)
    else:
        analyses = parser.parse_directory(manifest_path)
        analysis = parser.combine_analyses(analyses)
    
    # Deploy each manifest
    results = []
    for resource in analysis.resources:
        if dry_run:
            result = client.test_manifest_deployment(resource, namespace)
        else:
            result = client.deploy_manifest(resource, namespace)
        results.append(result)
    
    # Display results
    _display_deployment_results(results, dry_run)
    
    # Check for SCC-related failures
    scc_failures = [r for r in results if not r.success and r.scc_issues]
    if scc_failures:
        console.print("\n[yellow]⚠ Found SCC-related deployment failures[/yellow]")
        if click.confirm("Would you like to use AI to analyze and fix these issues?"):
            _handle_scc_failures(scc_failures, analysis, client)

@cli.command()
@click.argument('manifest_path', type=click.Path(exists=True))
@click.option('--scc-name', '-n', help='Name of SCC to create/update')
@click.option('--kubeconfig', '-k', type=click.Path(), help='Path to kubeconfig file')
@click.option('--ai-provider', type=click.Choice(['openai', 'anthropic', 'mistral']), default='openai', help='AI provider')
@click.option('--api-key', help='API key for AI provider')
@click.option('--max-iterations', type=int, default=3, help='Maximum AI adjustment iterations')
@click.pass_context
def auto_deploy(ctx, manifest_path, scc_name, kubeconfig, ai_provider, api_key, max_iterations):
    """Automatically deploy manifests with AI-powered SCC adjustment"""
    console.print(f"[bold blue]Auto-deploying with AI assistance: {manifest_path}[/bold blue]")
    
    # Setup AI agent
    ai_agent = SCCAIAgent(AIProvider(ai_provider), api_key)
    
    # Connect to cluster
    client = OpenShiftClient(kubeconfig)
    if not client.connect():
        console.print("[red]✗ Failed to connect to cluster[/red]")
        sys.exit(1)
    
    # Parse manifests
    parser = ManifestParser()
    if os.path.isfile(manifest_path):
        analysis = parser.parse_file(manifest_path)
    else:
        analyses = parser.parse_directory(manifest_path)
        analysis = parser.combine_analyses(analyses)
    
    # Generate or update SCC based on existing associations
    scc_generator = SCCGenerator()
    if not scc_name:
        scc_name = f"ai-generated-{hash(manifest_path) % 10000}"
    
    # Check for existing SCC associations and update if found
    current_scc = scc_generator.generate_or_update_scc(analysis, scc_name, client)
    operation = "updated" if client.find_existing_scc_for_service_accounts([
        {'name': sa.name, 'namespace': sa.namespace} for sa in analysis.service_accounts
    ]) else "created"
    
    console.print(f"[bold]SCC {operation}: {current_scc['metadata']['name']}[/bold]")
    
    # Deploy SCC
    if not client.create_scc(current_scc):
        console.print("[red]✗ Failed to create initial SCC[/red]")
        sys.exit(1)
    
    # Create ClusterRole for SCC
    clusterrole = scc_generator.create_clusterrole(scc_name)
    if not client.create_clusterrole(clusterrole):
        console.print("[red]✗ Failed to create ClusterRole[/red]")
        sys.exit(1)
    
    # Create role bindings
    for sa in analysis.service_accounts:
        rolebinding = scc_generator.create_rolebinding(scc_name, sa.name, sa.namespace)
        client.create_rolebinding(rolebinding)
    
    # Iterative deployment with AI adjustment
    iteration = 0
    while iteration < max_iterations:
        iteration += 1
        console.print(f"\n[bold]Deployment attempt {iteration}[/bold]")
        
        # Try to deploy manifests
        deployment_results = []
        for resource in analysis.resources:
            result = client.deploy_manifest(resource)
            deployment_results.append(result)
        
        # Check for failures
        failures = [r for r in deployment_results if not r.success]
        if not failures:
            console.print("[green]✓ All manifests deployed successfully![/green]")
            break
        
        # Focus on SCC-related failures
        scc_failures = [r for r in failures if r.scc_issues]
        if not scc_failures:
            console.print("[yellow]Non-SCC related failures detected[/yellow]")
            _display_deployment_results(deployment_results, False)
            break
        
        console.print(f"[yellow]Found {len(scc_failures)} SCC-related failures[/yellow]")
        
        # Use AI to analyze and adjust
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("AI analyzing deployment failures...", total=None)
            
            ai_analysis = ai_agent.analyze_deployment_failure(
                scc_failures[0], current_scc, analysis
            )
            
            progress.update(task, description="AI analysis complete")
        
        if not ai_analysis.success:
            console.print(f"[red]AI analysis failed: {ai_analysis.error_analysis}[/red]")
            break
        
        # Display AI analysis
        console.print("\n[bold]AI Analysis Results:[/bold]")
        console.print(ai_agent.get_adjustment_summary(ai_analysis))
        
        # Apply AI adjustments
        if ai_analysis.suggested_adjustments:
            adjusted_scc = ai_agent.apply_ai_adjustments(current_scc, ai_analysis)
            
            # Update SCC in cluster
            if client.update_scc(adjusted_scc):
                console.print("[green]✓ SCC updated with AI adjustments[/green]")
                current_scc = adjusted_scc
            else:
                console.print("[red]✗ Failed to update SCC[/red]")
                break
        else:
            console.print("[yellow]No AI adjustments suggested[/yellow]")
            break
    
    if iteration >= max_iterations:
        console.print(f"[red]Maximum iterations ({max_iterations}) reached[/red]")
    
    # Final deployment results
    _display_deployment_results(deployment_results, False)

@cli.command()
@click.argument('scc_name')
@click.option('--kubeconfig', '-k', type=click.Path(), help='Path to kubeconfig file')
@click.option('--output', '-o', type=click.Path(), help='Output file for SCC')
@click.pass_context
def get_scc(ctx, scc_name, kubeconfig, output):
    """Get SCC from cluster"""
    client = OpenShiftClient(kubeconfig)
    if not client.connect():
        console.print("[red]✗ Failed to connect to cluster[/red]")
        sys.exit(1)
    
    scc = client.get_scc(scc_name)
    if scc:
        if output:
            with open(output, 'w') as f:
                yaml.dump(scc, f, default_flow_style=False)
            console.print(f"[green]SCC saved to: {output}[/green]")
        else:
            console.print(Syntax(yaml.dump(scc, default_flow_style=False), "yaml"))
    else:
        console.print(f"[red]SCC '{scc_name}' not found[/red]")

@cli.command()
@click.option('--kubeconfig', '-k', type=click.Path(), help='Path to kubeconfig file')
@click.option('--output', '-o', type=click.Path(), help='Output file for SCC list')
@click.pass_context
def list_sccs(ctx, kubeconfig, output):
    """List all SCCs in cluster"""
    client = OpenShiftClient(kubeconfig)
    if not client.connect():
        console.print("[red]✗ Failed to connect to cluster[/red]")
        sys.exit(1)
    
    sccs = client.list_sccs()
    
    if output:
        with open(output, 'w') as f:
            yaml.dump(sccs, f, default_flow_style=False)
        console.print(f"[green]SCCs saved to: {output}[/green]")
    else:
        table = Table(title="Security Context Constraints")
        table.add_column("Name", style="cyan")
        table.add_column("Priority", style="white")
        table.add_column("Privileged", style="red")
        table.add_column("Host Network", style="yellow")
        table.add_column("Run As User", style="green")
        
        for scc in sccs:
            metadata = scc.get('metadata', {})
            name = metadata.get('name', 'Unknown')
            priority = str(scc.get('priority', 'N/A'))
            privileged = "Yes" if scc.get('allowPrivilegedContainer', False) else "No"
            host_network = "Yes" if scc.get('allowHostNetwork', False) else "No"
            run_as_user = scc.get('runAsUser', {}).get('type', 'Unknown')
            
            table.add_row(name, priority, privileged, host_network, run_as_user)
        
        console.print(table)

@cli.command()
@click.option('--examples', is_flag=True, help='Show example configurations')
@click.pass_context
def config(ctx, examples):
    """Show configuration options"""
    if examples:
        _show_config_examples()
    else:
        _show_config_help()

def _display_analysis_table(analysis):
    """Display analysis results in table format"""
    # Security requirements table
    if analysis.security_requirements:
        table = Table(title="Security Requirements")
        table.add_column("Type", style="cyan")
        table.add_column("Value", style="white")
        table.add_column("Severity", style="red")
        table.add_column("Resource", style="green")
        table.add_column("Context", style="yellow")
        
        for req in analysis.security_requirements:
            table.add_row(
                req.requirement_type.value,
                str(req.value),
                req.severity,
                f"{req.resource_kind}/{req.resource_name}",
                req.context
            )
        
        console.print(table)
    
    # Service accounts table
    if analysis.service_accounts:
        table = Table(title="Service Accounts")
        table.add_column("Name", style="cyan")
        table.add_column("Namespace", style="white")
        table.add_column("Resources", style="green")
        
        for sa in analysis.service_accounts:
            table.add_row(
                sa.name,
                sa.namespace,
                ", ".join(sa.resources)
            )
        
        console.print(table)

def _display_scc_status_table(scc_status):
    """Display SCC status information in table format"""
    table = Table(title="SCC Status Analysis")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")
    
    # Status color coding
    status_colors = {
        'no_scc_needed': 'green',
        'scc_needed': 'yellow',
        'scc_exists_may_need_update': 'orange'
    }
    
    status_color = status_colors.get(scc_status['status'], 'white')
    
    table.add_row("Status", f"[{status_color}]{scc_status['status'].replace('_', ' ').title()}[/{status_color}]")
    table.add_row("Message", scc_status['message'])
    table.add_row("Suggested SCC", scc_status['suggested_scc'])
    
    if scc_status['existing_scc']:
        table.add_row("Existing SCC", scc_status['existing_scc'])
    
    console.print(table)

def _analyze_scc_status(analysis):
    """Analyze SCC status and requirements"""
    scc_generator = SCCGenerator()
    
    # Check if there are any security requirements that need SCC
    if not analysis.security_requirements:
        return {
            'status': 'no_scc_needed',
            'message': 'No SCC needed - manifests use only basic security contexts',
            'suggested_scc': 'restricted',
            'existing_scc': None
        }
    
    # Check if manifest already contains an SCC
    from ..yaml_parser.manifest_parser import ManifestParser
    parser = ManifestParser()
    rbac_resources = parser.extract_existing_rbac_resources(analysis.file_path)
    existing_scc = rbac_resources.get("scc")
    
    # Suggest existing SCC that could work
    suggested_scc = scc_generator.suggest_existing_scc(analysis)
    
    # Determine status based on requirements and existing SCC
    if existing_scc:
        # Check if existing SCC needs to be updated
        # For now, assume it might need updating if there are new requirements
        return {
            'status': 'scc_exists_may_need_update',
            'message': f'Found existing SCC "{existing_scc["name"]}" - may need updates based on new requirements',
            'suggested_scc': suggested_scc,
            'existing_scc': existing_scc["name"]
        }
    else:
        # No existing SCC, need to create one
        return {
            'status': 'scc_needed',
            'message': f'SCC required - recommend creating new SCC or using existing "{suggested_scc}" SCC',
            'suggested_scc': suggested_scc,
            'existing_scc': None
        }

def _display_summary_panel(summary):
    """Display summary information in a panel"""
    content = f"""
**Resources**: {summary['total_resources']}
**Security Requirements**: {summary['total_security_requirements']}
**Service Accounts**: {summary['total_service_accounts']}
**Namespaces**: {', '.join(summary['namespaces'])}
**Errors**: {summary['errors']}
**Warnings**: {summary['warnings']}
**SCC Status**: {summary.get('scc_status', {}).get('message', 'Not analyzed')}
    """
    
    console.print(Panel(Markdown(content), title="Analysis Summary", expand=False))

def _display_deployment_results(results, dry_run=False):
    """Display deployment results"""
    action = "Dry-run" if dry_run else "Deployment"
    
    table = Table(title=f"{action} Results")
    table.add_column("Resource", style="cyan")
    table.add_column("Namespace", style="white")
    table.add_column("Status", style="green")
    table.add_column("Error", style="red")
    
    for result in results:
        status = "✓ Success" if result.success else "✗ Failed"
        error = result.error_message[:50] + "..." if result.error_message and len(result.error_message) > 50 else result.error_message or ""
        
        table.add_row(
            f"{result.resource_kind}/{result.resource_name}",
            result.namespace,
            status,
            error
        )
    
    console.print(table)

def _handle_scc_failures(failures, analysis, client):
    """Handle SCC-related deployment failures"""
    console.print("[yellow]Starting AI-powered SCC adjustment...[/yellow]")
    # Implementation would go here
    pass

def _show_config_examples():
    """Show configuration examples"""
    examples = """
# Example kubeconfig content
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://api.my-cluster.com:6443
    certificate-authority-data: <base64-encoded-ca-cert>
  name: my-cluster
contexts:
- context:
    cluster: my-cluster
    user: my-user
  name: my-context
current-context: my-context
users:
- name: my-user
  user:
    token: <token>

# Example AI provider configuration
export OPENAI_API_KEY=your-api-key-here
export ANTHROPIC_API_KEY=your-api-key-here
    """
    
    console.print(Panel(Syntax(examples, "yaml"), title="Configuration Examples"))

def _show_config_help():
    """Show configuration help"""
    help_text = """
The OpenShift SCC AI Agent can be configured through:

1. **Environment Variables**:
   - OPENAI_API_KEY: OpenAI API key for AI analysis
   - ANTHROPIC_API_KEY: Anthropic API key
   - KUBECONFIG: Path to kubeconfig file

2. **Command Line Options**:
   - --kubeconfig: Path to kubeconfig file
   - --ai-provider: AI provider (openai, anthropic, mistral)
   - --api-key: API key for AI provider

3. **Configuration File**:
   - Use --config to specify a configuration file (not implemented yet)

For more information, see the documentation.
    """
    
    console.print(Panel(help_text, title="Configuration Help"))

if __name__ == '__main__':
    cli() 