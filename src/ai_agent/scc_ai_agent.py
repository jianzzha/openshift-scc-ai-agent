import json
import os
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import re
from loguru import logger
import openai
from langchain.llms import OpenAI
from langchain.chat_models import ChatOpenAI
from langchain.schema import HumanMessage, SystemMessage
from langchain.prompts import PromptTemplate
from ..yaml_parser.manifest_parser import ManifestAnalysis, SecurityRequirement, SecurityRequirementType
from ..openshift_client.client import DeploymentResult

class AIProvider(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    MISTRAL = "mistral"
    LOCAL = "local"

@dataclass
class SCCAdjustment:
    """Represents an AI-suggested SCC adjustment"""
    field: str
    current_value: Any
    suggested_value: Any
    reason: str
    confidence: float
    impact: str  # low, medium, high
    
@dataclass
class AIAnalysis:
    """Result of AI analysis of SCC deployment failure"""
    success: bool
    error_analysis: str
    root_cause: str
    suggested_adjustments: List[SCCAdjustment]
    alternative_approaches: List[str]
    security_implications: List[str]
    confidence_score: float

class SCCAIAgent:
    """AI Agent for analyzing and adjusting Security Context Constraints"""
    
    def __init__(self, ai_provider: AIProvider = AIProvider.OPENAI, api_key: Optional[str] = None):
        """
        Initialize the AI agent
        
        Args:
            ai_provider: AI provider to use
            api_key: API key for the AI provider
        """
        self.ai_provider = ai_provider
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.client = None
        self.chat_model = None
        
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize the AI client based on provider"""
        if self.ai_provider == AIProvider.OPENAI:
            if not self.api_key:
                logger.error("OpenAI API key not provided")
                return
            
            openai.api_key = self.api_key
            self.client = openai
            self.chat_model = ChatOpenAI(
                model_name="gpt-4",
                temperature=0.1,
                openai_api_key=self.api_key
            )
            logger.info("Initialized OpenAI client")
        
        elif self.ai_provider == AIProvider.ANTHROPIC:
            # TODO: Implement Anthropic client
            logger.warning("Anthropic provider not yet implemented")
        
        elif self.ai_provider == AIProvider.MISTRAL:
            # TODO: Implement Mistral client
            logger.warning("Mistral provider not yet implemented")
        
        elif self.ai_provider == AIProvider.LOCAL:
            # TODO: Implement local model client
            logger.warning("Local provider not yet implemented")
    
    def analyze_deployment_failure(self, 
                                   deployment_result: DeploymentResult,
                                   current_scc: Dict[str, Any],
                                   manifest_analysis: ManifestAnalysis) -> AIAnalysis:
        """
        Analyze a deployment failure and suggest SCC adjustments
        
        Args:
            deployment_result: Result of failed deployment
            current_scc: Current SCC configuration
            manifest_analysis: Analysis of the manifest that failed
            
        Returns:
            AIAnalysis: AI analysis with suggested adjustments
        """
        logger.info(f"Analyzing deployment failure for {deployment_result.resource_name}")
        
        if not self.client:
            return AIAnalysis(
                success=False,
                error_analysis="AI client not initialized",
                root_cause="Configuration error",
                suggested_adjustments=[],
                alternative_approaches=[],
                security_implications=[],
                confidence_score=0.0
            )
        
        try:
            # Prepare context for AI analysis
            context = self._prepare_analysis_context(deployment_result, current_scc, manifest_analysis)
            
            # Get AI analysis
            analysis = self._get_ai_analysis(context)
            
            # Parse AI response into structured format
            structured_analysis = self._parse_ai_analysis(analysis)
            
            logger.info(f"AI analysis completed with confidence: {structured_analysis.confidence_score}")
            return structured_analysis
            
        except Exception as e:
            logger.error(f"Error in AI analysis: {str(e)}")
            return AIAnalysis(
                success=False,
                error_analysis=f"AI analysis failed: {str(e)}",
                root_cause="AI processing error",
                suggested_adjustments=[],
                alternative_approaches=[],
                security_implications=[],
                confidence_score=0.0
            )
    
    def suggest_scc_optimization(self, 
                                current_scc: Dict[str, Any],
                                manifest_analysis: ManifestAnalysis) -> AIAnalysis:
        """
        Suggest optimizations for an SCC based on actual usage patterns
        
        Args:
            current_scc: Current SCC configuration
            manifest_analysis: Analysis of manifests using this SCC
            
        Returns:
            AIAnalysis: AI analysis with optimization suggestions
        """
        logger.info(f"Analyzing SCC '{current_scc['metadata']['name']}' for optimization")
        
        if not self.client:
            return AIAnalysis(
                success=False,
                error_analysis="AI client not initialized",
                root_cause="Configuration error",
                suggested_adjustments=[],
                alternative_approaches=[],
                security_implications=[],
                confidence_score=0.0
            )
        
        try:
            # Prepare context for optimization analysis
            context = self._prepare_optimization_context(current_scc, manifest_analysis)
            
            # Get AI analysis
            analysis = self._get_ai_optimization_analysis(context)
            
            # Parse AI response into structured format
            structured_analysis = self._parse_ai_analysis(analysis)
            
            logger.info(f"SCC optimization analysis completed")
            return structured_analysis
            
        except Exception as e:
            logger.error(f"Error in SCC optimization analysis: {str(e)}")
            return AIAnalysis(
                success=False,
                error_analysis=f"Optimization analysis failed: {str(e)}",
                root_cause="AI processing error",
                suggested_adjustments=[],
                alternative_approaches=[],
                security_implications=[],
                confidence_score=0.0
            )
    
    def _prepare_analysis_context(self, 
                                  deployment_result: DeploymentResult,
                                  current_scc: Dict[str, Any],
                                  manifest_analysis: ManifestAnalysis) -> Dict[str, Any]:
        """Prepare context for AI analysis"""
        return {
            "deployment_failure": {
                "resource_name": deployment_result.resource_name,
                "resource_kind": deployment_result.resource_kind,
                "namespace": deployment_result.namespace,
                "error_message": deployment_result.error_message,
                "scc_issues": deployment_result.scc_issues or []
            },
            "current_scc": current_scc,
            "security_requirements": [
                {
                    "type": req.requirement_type.value,
                    "value": req.value,
                    "severity": req.severity,
                    "context": req.context
                }
                for req in manifest_analysis.security_requirements
            ],
            "service_accounts": [
                {
                    "name": sa.name,
                    "namespace": sa.namespace,
                    "resources": sa.resources
                }
                for sa in manifest_analysis.service_accounts
            ],
            "namespaces": list(manifest_analysis.namespaces),
            "manifest_summary": {
                "total_resources": len(manifest_analysis.resources),
                "total_security_requirements": len(manifest_analysis.security_requirements),
                "errors": manifest_analysis.errors,
                "warnings": manifest_analysis.warnings
            }
        }
    
    def _prepare_optimization_context(self, 
                                      current_scc: Dict[str, Any],
                                      manifest_analysis: ManifestAnalysis) -> Dict[str, Any]:
        """Prepare context for SCC optimization analysis"""
        return {
            "current_scc": current_scc,
            "actual_requirements": [
                {
                    "type": req.requirement_type.value,
                    "value": req.value,
                    "severity": req.severity,
                    "context": req.context
                }
                for req in manifest_analysis.security_requirements
            ],
            "usage_patterns": {
                "service_accounts": len(manifest_analysis.service_accounts),
                "namespaces": len(manifest_analysis.namespaces),
                "workload_types": list(set(res.get('kind', '') for res in manifest_analysis.resources))
            },
            "security_analysis": {
                "high_risk_requirements": [
                    req for req in manifest_analysis.security_requirements
                    if req.severity in ['high', 'critical']
                ],
                "potential_over_permissions": self._analyze_over_permissions(current_scc, manifest_analysis)
            }
        }
    
    def _get_ai_analysis(self, context: Dict[str, Any]) -> str:
        """Get AI analysis of deployment failure"""
        prompt = self._create_failure_analysis_prompt(context)
        
        if self.ai_provider == AIProvider.OPENAI:
            messages = [
                SystemMessage(content=self._get_system_prompt()),
                HumanMessage(content=prompt)
            ]
            
            response = self.chat_model(messages)
            return response.content
        
        return "AI analysis not available"
    
    def _get_ai_optimization_analysis(self, context: Dict[str, Any]) -> str:
        """Get AI analysis for SCC optimization"""
        prompt = self._create_optimization_prompt(context)
        
        if self.ai_provider == AIProvider.OPENAI:
            messages = [
                SystemMessage(content=self._get_optimization_system_prompt()),
                HumanMessage(content=prompt)
            ]
            
            response = self.chat_model(messages)
            return response.content
        
        return "AI optimization analysis not available"
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for failure analysis"""
        return """You are an expert OpenShift Security Context Constraints (SCC) specialist. Your role is to analyze deployment failures and provide precise, actionable recommendations for SCC adjustments.

Key responsibilities:
1. Analyze deployment failures and identify root causes
2. Suggest minimal, secure SCC adjustments
3. Explain security implications of suggested changes
4. Provide alternative approaches when possible
5. Maintain principle of least privilege

Guidelines:
- Always prioritize security over convenience
- Suggest the most restrictive SCC that will allow deployment
- Explain the reasoning behind each suggestion
- Highlight potential security risks
- Provide confidence levels for recommendations"""
    
    def _get_optimization_system_prompt(self) -> str:
        """Get the system prompt for optimization analysis"""
        return """You are an expert OpenShift Security Context Constraints (SCC) optimization specialist. Your role is to analyze existing SCCs and suggest optimizations based on actual usage patterns.

Key responsibilities:
1. Identify over-permissioned SCCs based on actual usage
2. Suggest tightening of unnecessary permissions
3. Recommend security improvements
4. Identify potential security risks
5. Maintain workload functionality

Guidelines:
- Follow principle of least privilege
- Only remove permissions not actually used
- Suggest gradual optimization approach
- Explain impact of each optimization
- Provide rollback strategies"""
    
    def _create_failure_analysis_prompt(self, context: Dict[str, Any]) -> str:
        """Create prompt for failure analysis"""
        return f"""Analyze the following OpenShift deployment failure and provide recommendations:

DEPLOYMENT FAILURE:
- Resource: {context['deployment_failure']['resource_kind']}/{context['deployment_failure']['resource_name']}
- Namespace: {context['deployment_failure']['namespace']}
- Error: {context['deployment_failure']['error_message']}
- SCC Issues: {context['deployment_failure']['scc_issues']}

CURRENT SCC:
{json.dumps(context['current_scc'], indent=2)}

SECURITY REQUIREMENTS:
{json.dumps(context['security_requirements'], indent=2)}

SERVICE ACCOUNTS:
{json.dumps(context['service_accounts'], indent=2)}

Please provide a detailed analysis in the following JSON format:
{{
  "error_analysis": "Detailed analysis of what went wrong",
  "root_cause": "Primary cause of the failure",
  "suggested_adjustments": [
    {{
      "field": "SCC field to adjust",
      "current_value": "current value",
      "suggested_value": "suggested value",
      "reason": "why this change is needed",
      "confidence": 0.9,
      "impact": "high/medium/low"
    }}
  ],
  "alternative_approaches": [
    "Alternative solution 1",
    "Alternative solution 2"
  ],
  "security_implications": [
    "Security implication 1",
    "Security implication 2"
  ],
  "confidence_score": 0.85
}}"""
    
    def _create_optimization_prompt(self, context: Dict[str, Any]) -> str:
        """Create prompt for optimization analysis"""
        return f"""Analyze the following OpenShift SCC for optimization opportunities:

CURRENT SCC:
{json.dumps(context['current_scc'], indent=2)}

ACTUAL REQUIREMENTS:
{json.dumps(context['actual_requirements'], indent=2)}

USAGE PATTERNS:
{json.dumps(context['usage_patterns'], indent=2)}

SECURITY ANALYSIS:
{json.dumps(context['security_analysis'], indent=2)}

Please provide optimization recommendations in the following JSON format:
{{
  "error_analysis": "Analysis of current SCC configuration",
  "root_cause": "Areas for improvement",
  "suggested_adjustments": [
    {{
      "field": "SCC field to optimize",
      "current_value": "current value",
      "suggested_value": "optimized value",
      "reason": "why this optimization is beneficial",
      "confidence": 0.9,
      "impact": "high/medium/low"
    }}
  ],
  "alternative_approaches": [
    "Alternative optimization approach 1",
    "Alternative optimization approach 2"
  ],
  "security_implications": [
    "Security benefit 1",
    "Security benefit 2"
  ],
  "confidence_score": 0.85
}}"""
    
    def _parse_ai_analysis(self, ai_response: str) -> AIAnalysis:
        """Parse AI response into structured format"""
        try:
            # Try to extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                parsed = json.loads(json_str)
            else:
                # Fallback to simple parsing
                return self._parse_ai_response_fallback(ai_response)
            
            # Convert to structured format
            adjustments = []
            for adj in parsed.get('suggested_adjustments', []):
                adjustments.append(SCCAdjustment(
                    field=adj.get('field', ''),
                    current_value=adj.get('current_value'),
                    suggested_value=adj.get('suggested_value'),
                    reason=adj.get('reason', ''),
                    confidence=adj.get('confidence', 0.5),
                    impact=adj.get('impact', 'medium')
                ))
            
            return AIAnalysis(
                success=True,
                error_analysis=parsed.get('error_analysis', ''),
                root_cause=parsed.get('root_cause', ''),
                suggested_adjustments=adjustments,
                alternative_approaches=parsed.get('alternative_approaches', []),
                security_implications=parsed.get('security_implications', []),
                confidence_score=parsed.get('confidence_score', 0.5)
            )
            
        except Exception as e:
            logger.error(f"Error parsing AI response: {str(e)}")
            return self._parse_ai_response_fallback(ai_response)
    
    def _parse_ai_response_fallback(self, ai_response: str) -> AIAnalysis:
        """Fallback parser for AI response"""
        return AIAnalysis(
            success=True,
            error_analysis=ai_response,
            root_cause="Unable to parse structured response",
            suggested_adjustments=[],
            alternative_approaches=[],
            security_implications=[],
            confidence_score=0.3
        )
    
    def _analyze_over_permissions(self, 
                                  current_scc: Dict[str, Any],
                                  manifest_analysis: ManifestAnalysis) -> List[str]:
        """Analyze potential over-permissions in SCC"""
        over_permissions = []
        
        # Check for unused capabilities
        allowed_caps = current_scc.get('allowedCapabilities', [])
        required_caps = set()
        
        for req in manifest_analysis.security_requirements:
            if req.requirement_type == SecurityRequirementType.CAPABILITIES:
                caps = req.value if isinstance(req.value, list) else [req.value]
                required_caps.update(caps)
        
        for cap in allowed_caps:
            if cap not in required_caps and cap != "*":
                over_permissions.append(f"Unnecessary capability: {cap}")
        
        # Check for unused volume types
        allowed_volumes = current_scc.get('volumes', [])
        required_volumes = set()
        
        for req in manifest_analysis.security_requirements:
            if req.requirement_type == SecurityRequirementType.HOST_PATH:
                required_volumes.add('hostPath')
            elif req.requirement_type == SecurityRequirementType.VOLUMES:
                vol_types = req.value if isinstance(req.value, list) else [req.value]
                required_volumes.update(vol_types)
        
        # Add basic volumes that are commonly needed
        basic_volumes = {'configMap', 'secret', 'emptyDir', 'persistentVolumeClaim'}
        required_volumes.update(basic_volumes)
        
        for vol in allowed_volumes:
            if vol not in required_volumes and vol != "*":
                over_permissions.append(f"Unnecessary volume type: {vol}")
        
        # Check for unnecessary host access
        host_checks = [
            ('allowHostNetwork', SecurityRequirementType.HOST_NETWORK),
            ('allowHostPID', SecurityRequirementType.HOST_PID),
            ('allowHostIPC', SecurityRequirementType.HOST_IPC),
            ('allowPrivilegedContainer', SecurityRequirementType.PRIVILEGED)
        ]
        
        required_host_access = set(req.requirement_type for req in manifest_analysis.security_requirements)
        
        for scc_field, req_type in host_checks:
            if current_scc.get(scc_field, False) and req_type not in required_host_access:
                over_permissions.append(f"Unnecessary host access: {scc_field}")
        
        return over_permissions
    
    def apply_ai_adjustments(self, 
                             current_scc: Dict[str, Any],
                             ai_analysis: AIAnalysis) -> Dict[str, Any]:
        """
        Apply AI-suggested adjustments to an SCC
        
        Args:
            current_scc: Current SCC configuration
            ai_analysis: AI analysis with suggestions
            
        Returns:
            Dict: Updated SCC configuration
        """
        logger.info(f"Applying {len(ai_analysis.suggested_adjustments)} AI adjustments to SCC")
        
        updated_scc = current_scc.copy()
        
        for adjustment in ai_analysis.suggested_adjustments:
            if adjustment.confidence >= 0.7:  # Only apply high-confidence adjustments
                try:
                    # Handle nested fields
                    field_parts = adjustment.field.split('.')
                    current_dict = updated_scc
                    
                    # Navigate to the correct nested dictionary
                    for part in field_parts[:-1]:
                        if part not in current_dict:
                            current_dict[part] = {}
                        current_dict = current_dict[part]
                    
                    # Set the final value
                    current_dict[field_parts[-1]] = adjustment.suggested_value
                    
                    logger.info(f"Applied adjustment: {adjustment.field} = {adjustment.suggested_value}")
                    
                except Exception as e:
                    logger.error(f"Error applying adjustment {adjustment.field}: {str(e)}")
        
        return updated_scc
    
    def get_adjustment_summary(self, ai_analysis: AIAnalysis) -> str:
        """Get a human-readable summary of AI adjustments"""
        if not ai_analysis.suggested_adjustments:
            return "No adjustments suggested"
        
        summary = f"AI Analysis Summary (Confidence: {ai_analysis.confidence_score:.1%})\n"
        summary += f"Root Cause: {ai_analysis.root_cause}\n\n"
        
        summary += "Suggested Adjustments:\n"
        for i, adj in enumerate(ai_analysis.suggested_adjustments, 1):
            summary += f"{i}. {adj.field}: {adj.current_value} → {adj.suggested_value}\n"
            summary += f"   Reason: {adj.reason}\n"
            summary += f"   Confidence: {adj.confidence:.1%}, Impact: {adj.impact}\n\n"
        
        if ai_analysis.alternative_approaches:
            summary += "Alternative Approaches:\n"
            for i, alt in enumerate(ai_analysis.alternative_approaches, 1):
                summary += f"{i}. {alt}\n"
        
        if ai_analysis.security_implications:
            summary += "\nSecurity Implications:\n"
            for i, impl in enumerate(ai_analysis.security_implications, 1):
                summary += f"{i}. {impl}\n"
        
        return summary 