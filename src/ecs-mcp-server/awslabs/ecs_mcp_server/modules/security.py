# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Security module for ECS MCP Server.
This module provides tools and prompts for comprehensive ECS security analysis.
"""

from typing import Any, Dict, List, Optional

from fastmcp import FastMCP

from awslabs.ecs_mcp_server.api.security_analysis import analyze_ecs_security


def register_module(mcp: FastMCP) -> None:
    """Register security module tools and prompts with the MCP server."""

    @mcp.tool(name="analyze_ecs_security")
    async def mcp_analyze_ecs_security(
        cluster_names: Optional[List[str]] = None,
        regions: Optional[List[str]] = None,
        analysis_scope: Optional[str] = "basic",
    ) -> Dict[str, Any]:
        """
        Comprehensive security analysis tool for ECS deployments.

        This tool performs a thorough security assessment of your ECS infrastructure,
        analyzing cluster configurations, service settings, network security, IAM roles,
        and compliance with AWS security best practices.

        USAGE INSTRUCTIONS:
        1. Specify cluster names to analyze specific clusters, or leave empty to analyze all
        2. Specify regions to analyze, or leave empty to use the default region (us-east-1)
        3. Review the security recommendations and prioritize based on severity levels
        4. Use the detailed remediation steps to address identified security issues

        The analysis covers:
        - Cluster-level security configurations (Container Insights, execute command settings)
        - Service and task definition security (IAM roles, resource limits, privileged containers)
        - Network security (VPC configuration, security groups, load balancer settings)
        - Container security (image scanning, runtime security, secrets management)
        - Compliance checks (AWS Well-Architected Framework, industry standards)
        - Monitoring and logging security (CloudWatch, audit trails)

        Security recommendations are categorized by:
        - Severity: Critical, High, Medium, Low
        - Category: security, monitoring, compliance, network, iam, container
        - Resource: Specific AWS resource affected
        - Remediation: Step-by-step instructions to resolve issues

        Parameters:
            cluster_names: List of cluster names to analyze (optional, analyzes all if not provided)
            regions: List of regions to analyze (optional, defaults to us-east-1)
            analysis_scope: Scope of analysis (currently supports 'basic')

        Returns:
            Dictionary containing comprehensive security analysis results with recommendations,
            severity breakdown, and remediation guidance
        """
        return await analyze_ecs_security(
            cluster_names=cluster_names,
            regions=regions,
            analysis_scope=analysis_scope,
        )

    # Prompt patterns for security analysis
    @mcp.prompt("security analysis")
    def security_analysis_prompt():
        """User wants security analysis"""
        return ["analyze_ecs_security"]

    @mcp.prompt("security audit")
    def security_audit_prompt():
        """User wants security audit"""
        return ["analyze_ecs_security"]

    @mcp.prompt("security assessment")
    def security_assessment_prompt():
        """User wants security assessment"""
        return ["analyze_ecs_security"]

    @mcp.prompt("security review")
    def security_review_prompt():
        """User wants security review"""
        return ["analyze_ecs_security"]

    @mcp.prompt("security check")
    def security_check_prompt():
        """User wants security check"""
        return ["analyze_ecs_security"]

    @mcp.prompt("vulnerability assessment")
    def vulnerability_assessment_prompt():
        """User wants vulnerability assessment"""
        return ["analyze_ecs_security"]

    @mcp.prompt("compliance check")
    def compliance_check_prompt():
        """User wants compliance check"""
        return ["analyze_ecs_security"]

    @mcp.prompt("security posture")
    def security_posture_prompt():
        """User wants to assess security posture"""
        return ["analyze_ecs_security"]

    @mcp.prompt("ecs security")
    def ecs_security_prompt():
        """User wants ECS security analysis"""
        return ["analyze_ecs_security"]

    @mcp.prompt("container security")
    def container_security_prompt():
        """User wants container security analysis"""
        return ["analyze_ecs_security"]

    @mcp.prompt("network security")
    def network_security_prompt():
        """User wants network security analysis"""
        return ["analyze_ecs_security"]

    @mcp.prompt("iam security")
    def iam_security_prompt():
        """User wants IAM security analysis"""
        return ["analyze_ecs_security"]

    @mcp.prompt("security recommendations")
    def security_recommendations_prompt():
        """User wants security recommendations"""
        return ["analyze_ecs_security"]

    @mcp.prompt("security best practices")
    def security_best_practices_prompt():
        """User wants security best practices analysis"""
        return ["analyze_ecs_security"]

    @mcp.prompt("well architected security")
    def well_architected_security_prompt():
        """User wants Well-Architected security analysis"""
        return ["analyze_ecs_security"]
