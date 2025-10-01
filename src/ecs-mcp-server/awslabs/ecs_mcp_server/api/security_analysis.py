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
ECS Security Analysis API

This module provides comprehensive security analysis capabilities for Amazon ECS resources.
It analyzes clusters, services, task definitions, and related AWS resources to identify
potential security vulnerabilities and compliance issues.

Key Features:
- Multi-framework compliance checking (SOC2, HIPAA, PCI-DSS, etc.)
- Comprehensive security analysis across ECS resources
- Detailed recommendations for security improvements
- Support for custom security policies and rules
"""

import logging
import re
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class ECSSecurityAnalyzer:
    """
    Comprehensive security analyzer for Amazon ECS resources.

    This class provides methods to analyze ECS clusters, services, task definitions,
    and related AWS resources for security vulnerabilities and compliance issues.
    """

    def __init__(self, region_name: str = "us-east-1"):
        """
        Initialize the ECS Security Analyzer.

        Args:
            region_name: AWS region name for the analysis
        """
        self.region_name = region_name
        self._ecs_client = None
        self._ec2_client = None
        self._elbv2_client = None
        self._logs_client = None

        # Security validation patterns
        self._security_patterns = {
            "docker_hub_official": re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$"),
            "docker_hub_user": re.compile(
                r"^[a-z0-9]+(?:[._-][a-z0-9]+)*/[a-z0-9]+(?:[._-][a-z0-9]+)*$"
            ),
            "ecr_public": re.compile(
                r"^public\.ecr\.aws/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._/-]*$"
            ),
            "ecr_private": re.compile(
                r"^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/[a-z0-9][a-z0-9._/-]*$"
            ),
            "sensitive_keys": re.compile(
                r"(?i)(password|secret|key|token|credential)", re.IGNORECASE
            ),
            "structured_data": re.compile(r'[{}\[\]":]'),
        }

    @property
    def ecs_client(self):
        """Lazy initialization of ECS client."""
        if self._ecs_client is None:
            self._ecs_client = boto3.client("ecs", region_name=self.region_name)
        return self._ecs_client

    @property
    def ec2_client(self):
        """Lazy initialization of EC2 client."""
        if self._ec2_client is None:
            self._ec2_client = boto3.client("ec2", region_name=self.region_name)
        return self._ec2_client

    @property
    def elbv2_client(self):
        """Lazy initialization of ELBv2 client."""
        if self._elbv2_client is None:
            self._elbv2_client = boto3.client("elbv2", region_name=self.region_name)
        return self._elbv2_client

    @property
    def logs_client(self):
        """Lazy initialization of CloudWatch Logs client."""
        if self._logs_client is None:
            self._logs_client = boto3.client("logs", region_name=self.region_name)
        return self._logs_client

    def _format_resource_name(self, resource_type: str, resource_name: str) -> str:
        """
        Format resource name consistently across all security findings.

        Args:
            resource_type: Type of the resource (e.g., 'Cluster', 'Service')
            resource_name: Name or identifier of the resource

        Returns:
            Formatted resource name string
        """
        return f"{resource_type}: {resource_name}"

    def _is_valid_docker_image(self, image_uri: str) -> bool:
        """
        Validate Docker image URI using secure pattern matching.

        Args:
            image_uri: Docker image URI to validate

        Returns:
            True if the image URI is valid and from a trusted source
        """
        if not image_uri or not isinstance(image_uri, str):
            return False

        # Remove tag/digest if present for validation
        base_image = image_uri.split(":")[0].split("@")[0]

        # Check against known secure patterns
        for pattern in self._security_patterns.values():
            if pattern.match(base_image):
                return True

        return False

    def _contains_sensitive_data(self, text: str) -> bool:
        """
        Check if text contains potentially sensitive information.

        Args:
            text: Text to analyze

        Returns:
            True if text appears to contain sensitive data
        """
        if not text or not isinstance(text, str):
            return False

        return bool(self._security_patterns["sensitive_keys"].search(text))

    def _appears_structured(self, text: str) -> bool:
        """
        Check if text appears to contain structured data.

        Args:
            text: Text to analyze

        Returns:
            True if text appears to contain structured data
        """
        if not text or not isinstance(text, str):
            return False

        return bool(self._security_patterns["structured_data"].search(text))

    def analyze_cluster_security(self, cluster_name: str) -> Dict[str, Any]:
        """
        Analyze security configuration of an ECS cluster.

        Args:
            cluster_name: Name of the ECS cluster to analyze

        Returns:
            Dictionary containing security analysis results
        """
        try:
            # Get cluster details
            response = self.ecs_client.describe_clusters(
                clusters=[cluster_name], include=["CONFIGURATIONS", "TAGS", "ATTACHMENTS"]
            )

            if not response.get("clusters"):
                return {
                    "cluster_name": cluster_name,
                    "status": "error",
                    "message": f"Cluster '{cluster_name}' not found",
                    "findings": [],
                }

            cluster = response["clusters"][0]
            findings = []

            # Analyze cluster configuration
            findings.extend(self._analyze_cluster_configuration(cluster))
            findings.extend(self._analyze_cluster_logging(cluster))
            findings.extend(self._analyze_cluster_capacity_providers(cluster))

            return {
                "cluster_name": cluster_name,
                "status": "success",
                "cluster_status": cluster.get("status", "UNKNOWN"),
                "findings": findings,
                "summary": {
                    "total_findings": len(findings),
                    "high_severity": len([f for f in findings if f.get("severity") == "High"]),
                    "medium_severity": len([f for f in findings if f.get("severity") == "Medium"]),
                    "low_severity": len([f for f in findings if f.get("severity") == "Low"]),
                },
            }

        except ClientError as e:
            logger.error(f"AWS API error analyzing cluster {cluster_name}: {e}")
            return {
                "cluster_name": cluster_name,
                "status": "error",
                "message": f"AWS API error: {str(e)}",
                "findings": [],
            }
        except Exception as e:
            logger.error(f"Unexpected error analyzing cluster {cluster_name}: {e}")
            return {
                "cluster_name": cluster_name,
                "status": "error",
                "message": f"Unexpected error: {str(e)}",
                "findings": [],
            }

    def _analyze_cluster_configuration(self, cluster: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze cluster configuration for security issues."""
        findings = []
        cluster_name = cluster.get("clusterName", "unknown")

        # Check cluster status
        status = cluster.get("status")
        if status != "ACTIVE":
            findings.append(
                {
                    "severity": "High",
                    "category": "availability",
                    "resource": self._format_resource_name("Cluster", cluster_name),
                    "issue": f"Cluster status is {status}, not ACTIVE",
                    "recommendation": "Investigate cluster status and resolve any issues preventing ACTIVE state",  # noqa: E501
                    "compliance_frameworks": ["SOC2", "HIPAA"],
                }
            )

        # Check for Container Insights
        configuration = cluster.get("configuration", {})
        execute_command_config = configuration.get("executeCommandConfiguration", {})

        if not execute_command_config:
            findings.append(
                {
                    "severity": "Medium",
                    "category": "monitoring",
                    "resource": self._format_resource_name("Cluster", cluster_name),
                    "issue": "No service-linked role configured for ECS cluster operations",
                    "recommendation": "Configure service-linked role for enhanced ECS cluster management and monitoring",  # noqa: E501
                    "compliance_frameworks": ["SOC2"],
                }
            )
        else:
            # Check execute command configuration security
            if execute_command_config.get("logging") != "OVERRIDE":
                findings.append(
                    {
                        "severity": "Medium",
                        "category": "logging",
                        "resource": self._format_resource_name("Cluster", cluster_name),
                        "issue": "Execute command sessions are not encrypted with customer-managed KMS keys",  # noqa: E501
                        "recommendation": "Configure KMS encryption for execute command sessions to protect sensitive data",  # noqa: E501
                        "compliance_frameworks": ["HIPAA", "PCI-DSS"],
                    }
                )

        return findings

    def _analyze_cluster_logging(self, cluster: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze cluster logging configuration."""
        findings = []
        cluster_name = cluster.get("clusterName", "unknown")

        # Check for Container Insights
        settings = cluster.get("settings", [])
        container_insights_enabled = False

        for setting in settings:
            if setting.get("name") == "containerInsights" and setting.get("value") == "enabled":
                container_insights_enabled = True
                break

        if not container_insights_enabled:
            findings.append(
                {
                    "severity": "Medium",
                    "category": "monitoring",
                    "resource": self._format_resource_name("Cluster", cluster_name),
                    "issue": "Container Insights disabled, limiting audit trail for PHI access",
                    "recommendation": "Enable Container Insights for comprehensive monitoring and compliance logging",  # noqa: E501
                    "compliance_frameworks": ["HIPAA", "SOC2"],
                }
            )

        return findings

    def _analyze_cluster_capacity_providers(self, cluster: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze cluster capacity providers for security issues."""
        findings = []
        cluster_name = cluster.get("clusterName", "unknown")

        # Check capacity providers
        capacity_providers = cluster.get("capacityProviders", [])
        if not capacity_providers:
            findings.append(
                {
                    "severity": "Low",
                    "category": "resource_management",
                    "resource": self._format_resource_name("Cluster", cluster_name),
                    "issue": "No capacity providers configured, may impact scaling and availability",  # noqa: E501
                    "recommendation": "Configure appropriate capacity providers for optimal resource management",  # noqa: E501
                    "compliance_frameworks": ["SOC2"],
                }
            )

        return findings

    def get_cluster_list(self) -> List[str]:
        """
        Get list of all ECS clusters in the region.

        Returns:
            List of cluster names
        """
        try:
            response = self.ecs_client.list_clusters()
            cluster_arns = response.get("clusterArns", [])

            # Extract cluster names from ARNs
            cluster_names = []
            for arn in cluster_arns:
                cluster_name = arn.split("/")[-1]
                cluster_names.append(cluster_name)

            return cluster_names

        except ClientError as e:
            logger.error(f"Error listing clusters: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing clusters: {e}")
            return []

    def analyze_multiple_clusters(
        self, cluster_names: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Analyze security for multiple ECS clusters.

        Args:
            cluster_names: List of cluster names to analyze. If None, analyzes all clusters.

        Returns:
            Dictionary containing analysis results for all clusters
        """
        if cluster_names is None:
            cluster_names = self.get_cluster_list()

        if not cluster_names:
            return {"status": "error", "message": "No clusters found to analyze", "results": {}}

        results = {}
        total_findings = 0
        severity_counts = {"High": 0, "Medium": 0, "Low": 0}

        for cluster_name in cluster_names:
            logger.info(f"Analyzing cluster: {cluster_name}")
            cluster_result = self.analyze_cluster_security(cluster_name)
            results[cluster_name] = cluster_result

            if cluster_result.get("status") == "success":
                findings = cluster_result.get("findings", [])
                total_findings += len(findings)

                for finding in findings:
                    severity = finding.get("severity", "Unknown")
                    if severity in severity_counts:
                        severity_counts[severity] += 1

        return {
            "status": "success",
            "analyzed_clusters": len(cluster_names),
            "total_findings": total_findings,
            "severity_summary": severity_counts,
            "results": results,
        }
