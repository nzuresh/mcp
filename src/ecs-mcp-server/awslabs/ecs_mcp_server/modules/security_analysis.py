#!/usr/bin/env python3
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
Security Analysis Module for ECS MCP Server

This module provides comprehensive security analysis capabilities for ECS clusters,
including cluster security, service security, task definition security, container
instance security, and network security analysis.
"""

import logging
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP

from awslabs.ecs_mcp_server.api.security_analysis import ECSSecurityAnalyzer
from awslabs.ecs_mcp_server.utils.aws_utils import get_aws_session

logger = logging.getLogger(__name__)


def analyze_cluster_security(
    cluster_name: str,
    region: Optional[str] = None,
    profile: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyze security configuration of an ECS cluster.

    Args:
        cluster_name: Name of the ECS cluster to analyze
        region: AWS region (optional, uses default if not specified)
        profile: AWS profile to use (optional, uses default if not specified)

    Returns:
        Dictionary containing security analysis results for the cluster
    """
    try:
        logger.info(f"Starting cluster security analysis for: {cluster_name}")

        session = get_aws_session(region=region, profile=profile)
        analyzer = ECSSecurityAnalyzer(session)

        result = analyzer.analyze_cluster_security(cluster_name)

        logger.info(f"Cluster security analysis completed for: {cluster_name}")
        return result

    except Exception as e:
        logger.error(f"Error in cluster security analysis: {e}")
        return {
            "cluster_name": cluster_name,
            "status": "error",
            "message": f"Analysis failed: {str(e)}",
            "findings": [],
        }


def analyze_service_security(
    cluster_name: str,
    service_name: str,
    region: Optional[str] = None,
    profile: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyze security configuration of an ECS service.

    Args:
        cluster_name: Name of the ECS cluster
        service_name: Name of the ECS service to analyze
        region: AWS region (optional, uses default if not specified)
        profile: AWS profile to use (optional, uses default if not specified)

    Returns:
        Dictionary containing security analysis results for the service
    """
    try:
        logger.info(
            f"Starting service security analysis for: {service_name} in cluster: {cluster_name}"
        )

        session = get_aws_session(region=region, profile=profile)
        analyzer = ECSSecurityAnalyzer(session)

        result = analyzer.analyze_service_security(cluster_name, service_name)

        logger.info(f"Service security analysis completed for: {service_name}")
        return result

    except Exception as e:
        logger.error(f"Error in service security analysis: {e}")
        return {
            "cluster_name": cluster_name,
            "service_name": service_name,
            "status": "error",
            "message": f"Analysis failed: {str(e)}",
            "findings": [],
        }


def analyze_task_definition_security(
    task_definition_arn: str,
    region: Optional[str] = None,
    profile: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyze security configuration of an ECS task definition.

    Args:
        task_definition_arn: ARN or family:revision of the task definition
        region: AWS region (optional, uses default if not specified)
        profile: AWS profile to use (optional, uses default if not specified)

    Returns:
        Dictionary containing security analysis results for the task definition
    """
    try:
        logger.info(f"Starting task definition security analysis for: {task_definition_arn}")

        session = get_aws_session(region=region, profile=profile)
        analyzer = ECSSecurityAnalyzer(session)

        result = analyzer.analyze_task_definition_security(task_definition_arn)

        logger.info(f"Task definition security analysis completed for: {task_definition_arn}")
        return result

    except Exception as e:
        logger.error(f"Error in task definition security analysis: {e}")
        return {
            "task_definition_arn": task_definition_arn,
            "status": "error",
            "message": f"Analysis failed: {str(e)}",
            "findings": [],
        }


def analyze_comprehensive_security(
    cluster_name: str,
    region: Optional[str] = None,
    profile: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Perform comprehensive security analysis across all ECS components.

    This function analyzes:
    - Cluster security configuration
    - All services in the cluster
    - All task definitions used by services
    - Container instances security
    - Network security (VPC, subnets, security groups, load balancers)

    Args:
        cluster_name: Name of the ECS cluster to analyze
        region: AWS region (optional, uses default if not specified)
        profile: AWS profile to use (optional, uses default if not specified)

    Returns:
        Dictionary containing comprehensive security analysis results
    """
    try:
        logger.info(f"Starting comprehensive security analysis for cluster: {cluster_name}")

        session = get_aws_session(region=region, profile=profile)
        analyzer = ECSSecurityAnalyzer(session)

        result = analyzer.analyze_comprehensive_security(cluster_name)

        logger.info(f"Comprehensive security analysis completed for cluster: {cluster_name}")
        return result

    except Exception as e:
        logger.error(f"Error in comprehensive security analysis: {e}")
        return {
            "cluster_name": cluster_name,
            "status": "error",
            "message": f"Comprehensive analysis failed: {str(e)}",
            "findings": [],
        }


def generate_security_report(
    cluster_name: str,
    severity_filter: Optional[List[str]] = None,
    category_filter: Optional[List[str]] = None,
    compliance_framework: Optional[str] = None,
    include_recommendations: bool = True,
    format_type: str = "json",
    region: Optional[str] = None,
    profile: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate a comprehensive security report with filtering and formatting options.

    Args:
        cluster_name: Name of the ECS cluster
        severity_filter: List of severities to include (e.g., ["High", "Medium"])
        category_filter: List of categories to include (e.g., ["iam", "network_security"])
        compliance_framework: Filter findings by compliance framework (e.g., "SOC2", "HIPAA")
        include_recommendations: Whether to include detailed recommendations
        format_type: Output format ("json", "summary", "detailed")
        region: AWS region (optional, uses default if not specified)
        profile: AWS profile to use (optional, uses default if not specified)

    Returns:
        Formatted security report
    """
    try:
        logger.info(f"Generating security report for cluster: {cluster_name}")

        session = get_aws_session(region=region, profile=profile)
        analyzer = ECSSecurityAnalyzer(session)

        result = analyzer.generate_security_report(
            cluster_name=cluster_name,
            severity_filter=severity_filter,
            category_filter=category_filter,
            compliance_framework=compliance_framework,
            include_recommendations=include_recommendations,
            format_type=format_type,
        )

        logger.info(f"Security report generated for cluster: {cluster_name}")
        return result

    except Exception as e:
        logger.error(f"Error generating security report: {e}")
        return {
            "cluster_name": cluster_name,
            "status": "error",
            "message": f"Report generation failed: {str(e)}",
        }


def get_security_metrics(
    cluster_name: str,
    region: Optional[str] = None,
    profile: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Get security metrics and KPIs for monitoring and dashboards.

    Args:
        cluster_name: Name of the ECS cluster
        region: AWS region (optional, uses default if not specified)
        profile: AWS profile to use (optional, uses default if not specified)

    Returns:
        Dictionary containing security metrics
    """
    try:
        logger.info(f"Getting security metrics for cluster: {cluster_name}")

        session = get_aws_session(region=region, profile=profile)
        analyzer = ECSSecurityAnalyzer(session)

        result = analyzer.get_security_metrics(cluster_name)

        logger.info(f"Security metrics retrieved for cluster: {cluster_name}")
        return result

    except Exception as e:
        logger.error(f"Error getting security metrics: {e}")
        return {
            "cluster_name": cluster_name,
            "status": "error",
            "message": f"Metrics retrieval failed: {str(e)}",
        }


def register_module(mcp: FastMCP) -> None:
    """Register security analysis tools with the MCP server."""

    @mcp.tool()
    def analyze_ecs_cluster_security(
        cluster_name: str,
        region: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Analyze security configuration of an ECS cluster.

        This tool performs comprehensive security analysis of an ECS cluster including:
        - Container Insights configuration
        - Logging configuration
        - Encryption settings
        - Capacity provider security
        - Service discovery configuration

        Args:
            cluster_name: Name of the ECS cluster to analyze
            region: AWS region (optional, uses default if not specified)
            profile: AWS profile to use (optional, uses default if not specified)

        Returns:
            Dictionary containing security analysis results with findings and recommendations
        """
        return analyze_cluster_security(cluster_name, region, profile)

    @mcp.tool()
    def analyze_ecs_service_security(
        cluster_name: str,
        service_name: str,
        region: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Analyze security configuration of an ECS service.

        This tool performs security analysis of an ECS service including:
        - Service configuration security
        - Load balancer security
        - Auto scaling configuration
        - Network configuration
        - Service discovery security

        Args:
            cluster_name: Name of the ECS cluster
            service_name: Name of the ECS service to analyze
            region: AWS region (optional, uses default if not specified)
            profile: AWS profile to use (optional, uses default if not specified)

        Returns:
            Dictionary containing security analysis results with findings and recommendations
        """
        return analyze_service_security(cluster_name, service_name, region, profile)

    @mcp.tool()
    def analyze_ecs_task_definition_security(
        task_definition_arn: str,
        region: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Analyze security configuration of an ECS task definition.

        This tool performs comprehensive security analysis of a task definition including:
        - IAM role configuration
        - Container security settings
        - Network mode security
        - Resource limits and constraints
        - Environment variable security
        - Secrets management
        - Docker image security

        Args:
            task_definition_arn: ARN or family:revision of the task definition
                (e.g., 'my-app:1' or full ARN)
            region: AWS region (optional, uses default if not specified)
            profile: AWS profile to use (optional, uses default if not specified)

        Returns:
            Dictionary containing security analysis results with findings and recommendations
        """
        return analyze_task_definition_security(task_definition_arn, region, profile)

    @mcp.tool()
    def analyze_ecs_comprehensive_security(
        cluster_name: str,
        region: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Perform comprehensive security analysis across all ECS components.

        This tool performs end-to-end security analysis including:
        - Cluster security configuration
        - All services in the cluster
        - All task definitions used by services
        - Container instances security
        - Network security (VPC, subnets, security groups, load balancers)
        - Compliance framework mapping

        Args:
            cluster_name: Name of the ECS cluster to analyze
            region: AWS region (optional, uses default if not specified)
            profile: AWS profile to use (optional, uses default if not specified)

        Returns:
            Dictionary containing comprehensive security analysis results with aggregated findings
        """
        return analyze_comprehensive_security(cluster_name, region, profile)

    @mcp.tool()
    def generate_ecs_security_report(
        cluster_name: str,
        severity_filter: Optional[List[str]] = None,
        category_filter: Optional[List[str]] = None,
        compliance_framework: Optional[str] = None,
        include_recommendations: bool = True,
        format_type: str = "json",
        region: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive security report with filtering and formatting options.

        This tool creates detailed security reports with various filtering and formatting options:
        - Filter by severity levels (High, Medium, Low)
        - Filter by security categories (iam, network_security, container_security, etc.)
        - Filter by compliance frameworks (SOC2, HIPAA, PCI-DSS)
        - Multiple output formats (json, summary, detailed)

        Args:
            cluster_name: Name of the ECS cluster
            severity_filter: List of severities to include (e.g., ["High", "Medium"])
            category_filter: List of categories to include (e.g., ["iam", "network_security"])
            compliance_framework: Filter findings by compliance framework (e.g., "SOC2", "HIPAA")
            include_recommendations: Whether to include detailed recommendations
            format_type: Output format ("json", "summary", "detailed")
            region: AWS region (optional, uses default if not specified)
            profile: AWS profile to use (optional, uses default if not specified)

        Returns:
            Formatted security report based on specified criteria
        """
        return generate_security_report(
            cluster_name,
            severity_filter,
            category_filter,
            compliance_framework,
            include_recommendations,
            format_type,
            region,
            profile,
        )

    @mcp.tool()
    def get_ecs_security_metrics(
        cluster_name: str,
        region: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get security metrics and KPIs for monitoring and dashboards.

        This tool provides security metrics including:
        - Overall security score (0-100)
        - Severity distribution of findings
        - Category breakdown of security issues
        - Compliance framework coverage
        - Risk level assessment
        - Security trends and recommendations

        Args:
            cluster_name: Name of the ECS cluster
            region: AWS region (optional, uses default if not specified)
            profile: AWS profile to use (optional, uses default if not specified)

        Returns:
            Dictionary containing security metrics and KPIs
        """
        return get_security_metrics(cluster_name, region, profile)

    logger.info("Security analysis module registered successfully")
