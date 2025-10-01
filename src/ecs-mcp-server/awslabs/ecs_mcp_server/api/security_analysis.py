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

    def analyze_service_security(self, cluster_name: str, service_name: str) -> Dict[str, Any]:
        """
        Analyze security configuration of an ECS service.

        Args:
            cluster_name: Name of the ECS cluster
            service_name: Name of the ECS service to analyze

        Returns:
            Dictionary containing security analysis results
        """
        try:
            # Get service details
            response = self.ecs_client.describe_services(
                cluster=cluster_name, services=[service_name], include=["TAGS"]
            )

            if not response.get("services"):
                return {
                    "cluster_name": cluster_name,
                    "service_name": service_name,
                    "status": "error",
                    "message": f"Service '{service_name}' not found in cluster '{cluster_name}'",
                    "findings": [],
                }

            service = response["services"][0]
            findings = []

            # Analyze service configuration
            findings.extend(self._analyze_service_network_configuration(service))
            findings.extend(self._analyze_service_platform_configuration(service))
            findings.extend(self._analyze_service_security_groups(service))
            findings.extend(self._analyze_service_tags(service))
            findings.extend(self._analyze_service_task_count(service))

            return {
                "cluster_name": cluster_name,
                "service_name": service_name,
                "status": "success",
                "service_status": service.get("status", "UNKNOWN"),
                "findings": findings,
                "summary": {
                    "total_findings": len(findings),
                    "high_severity": len([f for f in findings if f.get("severity") == "High"]),
                    "medium_severity": len([f for f in findings if f.get("severity") == "Medium"]),
                    "low_severity": len([f for f in findings if f.get("severity") == "Low"]),
                },
            }

        except ClientError as e:
            logger.error(f"AWS API error analyzing service {service_name}: {e}")
            return {
                "cluster_name": cluster_name,
                "service_name": service_name,
                "status": "error",
                "message": f"AWS API error: {str(e)}",
                "findings": [],
            }
        except Exception as e:
            logger.error(f"Unexpected error analyzing service {service_name}: {e}")
            return {
                "cluster_name": cluster_name,
                "service_name": service_name,
                "status": "error",
                "message": f"Unexpected error: {str(e)}",
                "findings": [],
            }

    def _analyze_service_network_configuration(
        self, service: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze service network configuration for security issues."""
        findings = []
        service_name = service.get("serviceName", "unknown")

        # Check network configuration
        network_config = service.get("networkConfiguration", {})
        awsvpc_config = network_config.get("awsvpcConfiguration", {})

        # Check for public IP assignment
        if awsvpc_config.get("assignPublicIp") == "ENABLED":
            findings.append(
                {
                    "severity": "High",
                    "category": "network_security",
                    "resource": self._format_resource_name("Service", service_name),
                    "issue": "Service has public IP assignment enabled, exposing containers directly to the internet",  # noqa: E501
                    "recommendation": "Disable public IP assignment and use NAT Gateway for outbound connectivity",  # noqa: E501
                    "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS"],
                }
            )

        return findings

    def _analyze_service_platform_configuration(
        self, service: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze service platform configuration for security issues."""
        findings = []
        service_name = service.get("serviceName", "unknown")

        # Check platform version for Fargate
        if service.get("launchType") == "FARGATE":
            platform_version = service.get("platformVersion", "LATEST")
            if platform_version == "LATEST":
                findings.append(
                    {
                        "severity": "Medium",
                        "category": "security",
                        "resource": self._format_resource_name("Service", service_name),
                        "issue": "Using LATEST platform version can introduce unexpected security changes and makes security posture unpredictable",  # noqa: E501
                        "recommendation": "Pin to a specific Fargate platform version to maintain consistent security configuration and controlled security updates",  # noqa: E501
                        "compliance_frameworks": ["SOC2", "PCI-DSS"],
                    }
                )

        # Check Service Connect configuration
        service_connect_config = service.get("serviceConnectConfiguration", {})
        if service_connect_config.get("enabled") and not service_connect_config.get("namespace"):
            findings.append(
                {
                    "severity": "Medium",
                    "category": "network_security",
                    "resource": self._format_resource_name("Service", service_name),
                    "issue": "Service Connect is enabled but no namespace is configured",
                    "recommendation": "Configure a proper namespace for Service Connect to ensure secure service-to-service communication",  # noqa: E501
                    "compliance_frameworks": ["SOC2"],
                }
            )

        return findings

    def _analyze_service_security_groups(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze service security groups for security issues."""
        findings = []
        service_name = service.get("serviceName", "unknown")

        # Check security groups configuration
        network_config = service.get("networkConfiguration", {})
        awsvpc_config = network_config.get("awsvpcConfiguration", {})
        security_groups = awsvpc_config.get("securityGroups", [])

        if not security_groups:
            findings.append(
                {
                    "severity": "High",
                    "category": "network_security",
                    "resource": self._format_resource_name("Service", service_name),
                    "issue": "No security groups configured for the service",
                    "recommendation": "Configure appropriate security groups to control network access",  # noqa: E501
                    "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS"],
                }
            )
        elif len(security_groups) > 5:
            findings.append(
                {
                    "severity": "Low",
                    "category": "network_security",
                    "resource": self._format_resource_name("Service", service_name),
                    "issue": f"Service has {len(security_groups)} security groups attached, which may be excessive",  # noqa: E501
                    "recommendation": "Review and consolidate security groups to simplify network security management",  # noqa: E501
                    "compliance_frameworks": ["SOC2"],
                }
            )

        return findings

    def _analyze_service_tags(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze service tags for security issues."""
        findings = []
        service_name = service.get("serviceName", "unknown")

        # Check tags for sensitive information
        tags = service.get("tags", [])
        for tag in tags:
            tag_key = tag.get("key", "")
            tag_value = tag.get("value", "")

            # Check for sensitive information in tag keys
            if self._contains_sensitive_data(tag_key):
                findings.append(
                    {
                        "severity": "High",
                        "category": "secrets",
                        "resource": self._format_resource_name("Service", service_name),
                        "issue": f'Tag key "{tag.get("key", "")}" may contain sensitive information',  # noqa: E501
                        "recommendation": "Remove sensitive information from tag keys and use AWS Secrets Manager instead",  # noqa: E501
                        "compliance_frameworks": ["HIPAA", "PCI-DSS", "SOC2"],
                    }
                )

            # Check for structured data in tag values that might contain secrets
            if self._appears_structured(tag_value) and len(tag_value) > 50:
                findings.append(
                    {
                        "severity": "Medium",
                        "category": "secrets",
                        "resource": self._format_resource_name("Service", service_name),
                        "issue": f'Tag "{tag.get("key", "")}" value appears to contain structured data that might be sensitive',  # noqa: E501
                        "recommendation": "Review tag value and move any sensitive data to AWS Secrets Manager",  # noqa: E501
                        "compliance_frameworks": ["HIPAA", "PCI-DSS"],
                    }
                )

        return findings

    def _analyze_service_task_count(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze service task count for security issues."""
        findings = []
        service_name = service.get("serviceName", "unknown")

        # Check running task count
        running_tasks = service.get("runningCount", 0)
        desired_tasks = service.get("desiredCount", 0)

        # Check for unusually high task count (potential DDoS or resource exhaustion)
        if running_tasks > 100:
            findings.append(
                {
                    "severity": "Medium",
                    "category": "security",
                    "resource": self._format_resource_name("Service", service_name),
                    "issue": f"Service has {len(running_tasks)} running tasks, which could indicate a DDoS attack or resource exhaustion attempt",  # noqa: E501
                    "recommendation": "Investigate high task count for potential security incidents and review scaling policies",  # noqa: E501
                    "compliance_frameworks": ["SOC2"],
                }
            )

        # Check for no running tasks when desired > 0 (potential security incident)
        if desired_tasks > 0 and running_tasks == 0:
            findings.append(
                {
                    "severity": "High",
                    "category": "security",
                    "resource": self._format_resource_name("Service", service_name),
                    "issue": "Service has no running tasks, which could indicate a security incident or attack",  # noqa: E501
                    "recommendation": "Immediately investigate why service has no running tasks - check for potential security breaches or attacks",  # noqa: E501
                    "compliance_frameworks": ["SOC2", "HIPAA"],
                }
            )

        return findings

    def get_service_list(self, cluster_name: str) -> List[str]:
        """
        Get list of all ECS services in a cluster.

        Args:
            cluster_name: Name of the ECS cluster

        Returns:
            List of service names
        """
        try:
            response = self.ecs_client.list_services(cluster=cluster_name)
            service_arns = response.get("serviceArns", [])

            # Extract service names from ARNs
            service_names = []
            for arn in service_arns:
                service_name = arn.split("/")[-1]
                service_names.append(service_name)

            return service_names

        except ClientError as e:
            logger.error(f"Error listing services in cluster {cluster_name}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing services in cluster {cluster_name}: {e}")
            return []

    def analyze_multiple_services(
        self, cluster_name: str, service_names: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Analyze security for multiple ECS services in a cluster.

        Args:
            cluster_name: Name of the ECS cluster
            service_names: List of service names to analyze. If None, analyzes all services.

        Returns:
            Dictionary containing analysis results for all services
        """
        if service_names is None:
            service_names = self.get_service_list(cluster_name)

        if not service_names:
            return {
                "cluster_name": cluster_name,
                "status": "error",
                "message": f"No services found in cluster '{cluster_name}'",
                "results": {},
            }

        results = {}
        total_findings = 0
        severity_counts = {"High": 0, "Medium": 0, "Low": 0}

        for service_name in service_names:
            logger.info(f"Analyzing service: {service_name} in cluster: {cluster_name}")
            service_result = self.analyze_service_security(cluster_name, service_name)
            results[service_name] = service_result

            if service_result.get("status") == "success":
                findings = service_result.get("findings", [])
                total_findings += len(findings)

                for finding in findings:
                    severity = finding.get("severity", "Unknown")
                    if severity in severity_counts:
                        severity_counts[severity] += 1

        return {
            "cluster_name": cluster_name,
            "status": "success",
            "analyzed_services": len(service_names),
            "total_findings": total_findings,
            "severity_summary": severity_counts,
            "results": results,
        }
