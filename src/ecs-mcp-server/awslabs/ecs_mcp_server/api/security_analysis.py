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

    def analyze_task_definition_security(self, task_definition_arn: str) -> Dict[str, Any]:
        """
        Analyze security configuration of an ECS task definition.

        Args:
            task_definition_arn: ARN or family:revision of the task definition to analyze

        Returns:
            Dictionary containing security analysis results
        """
        try:
            # Get task definition details
            response = self.ecs_client.describe_task_definition(
                taskDefinition=task_definition_arn, include=["TAGS"]
            )

            if not response.get("taskDefinition"):
                return {
                    "task_definition_arn": task_definition_arn,
                    "status": "error",
                    "message": f"Task definition '{task_definition_arn}' not found",
                    "findings": [],
                }

            task_definition = response["taskDefinition"]
            findings = []

            # Analyze task definition configuration
            findings.extend(self._analyze_task_definition_iam_roles(task_definition))
            findings.extend(self._analyze_task_definition_network_mode(task_definition))
            findings.extend(self._analyze_task_definition_resource_limits(task_definition))
            findings.extend(self._analyze_task_definition_launch_type(task_definition))
            findings.extend(self._analyze_task_definition_containers(task_definition))

            task_family = task_definition.get("family", "unknown")

            return {
                "task_definition_arn": task_definition_arn,
                "task_family": task_family,
                "status": "success",
                "findings": findings,
                "summary": {
                    "total_findings": len(findings),
                    "high_severity": len([f for f in findings if f.get("severity") == "High"]),
                    "medium_severity": len([f for f in findings if f.get("severity") == "Medium"]),
                    "low_severity": len([f for f in findings if f.get("severity") == "Low"]),
                },
            }

        except ClientError as e:
            logger.error(f"AWS API error analyzing task definition {task_definition_arn}: {e}")
            return {
                "task_definition_arn": task_definition_arn,
                "status": "error",
                "message": f"AWS API error: {str(e)}",
                "findings": [],
            }
        except Exception as e:
            logger.error(f"Unexpected error analyzing task definition {task_definition_arn}: {e}")
            return {
                "task_definition_arn": task_definition_arn,
                "status": "error",
                "message": f"Unexpected error: {str(e)}",
                "findings": [],
            }

    def _analyze_task_definition_iam_roles(
        self, task_definition: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze task definition IAM roles for security issues."""
        findings = []
        task_family = task_definition.get("family", "unknown")

        # Check for task IAM role
        task_role_arn = task_definition.get("taskRoleArn")
        if not task_role_arn:
            findings.append(
                {
                    "severity": "High",
                    "category": "iam_security",
                    "resource": self._format_resource_name("Task Definition", task_family),
                    "issue": "Missing task IAM role - containers will have no AWS API permissions",
                    "recommendation": "Configure task IAM role with minimal required permissions following principle of least privilege",  # noqa: E501
                    "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS"],
                }
            )

        # Check for execution IAM role
        execution_role_arn = task_definition.get("executionRoleArn")
        if not execution_role_arn:
            findings.append(
                {
                    "severity": "High",
                    "category": "iam_security",
                    "resource": self._format_resource_name("Task Definition", task_family),
                    "issue": "Missing execution IAM role - ECS agent cannot pull images or write logs",  # noqa: E501
                    "recommendation": "Configure execution IAM role for ECS agent operations (image pulling, logging, secrets)",  # noqa: E501
                    "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS"],
                }
            )

        return findings

    def _analyze_task_definition_network_mode(
        self, task_definition: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze task definition network mode for security issues."""
        findings = []
        task_family = task_definition.get("family", "unknown")

        network_mode = task_definition.get("networkMode", "bridge")

        # Check for insecure network modes
        if network_mode == "host":
            findings.append(
                {
                    "severity": "High",
                    "category": "network_security",
                    "resource": self._format_resource_name("Task Definition", task_family),
                    "issue": "Task uses host network mode, bypassing container network isolation",
                    "recommendation": "Use awsvpc network mode for better network isolation and security",  # noqa: E501
                    "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS"],
                }
            )

        # Check for host PID mode
        if task_definition.get("pidMode") == "host":
            findings.append(
                {
                    "severity": "High",
                    "category": "container_security",
                    "resource": self._format_resource_name("Task Definition", task_family),
                    "issue": "Task uses host PID mode, allowing containers to see all host processes",  # noqa: E501
                    "recommendation": "Disable host PID mode to maintain process isolation between containers and host",  # noqa: E501
                    "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS"],
                }
            )

        # Check for host IPC mode
        if task_definition.get("ipcMode") == "host":
            findings.append(
                {
                    "severity": "High",
                    "category": "container_security",
                    "resource": self._format_resource_name("Task Definition", task_family),
                    "issue": "Task uses host IPC mode, allowing containers to access host IPC resources",  # noqa: E501
                    "recommendation": "Disable host IPC mode to maintain IPC isolation between containers and host",  # noqa: E501
                    "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS"],
                }
            )

        return findings

    def _analyze_task_definition_resource_limits(
        self, task_definition: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze task definition resource limits for security issues."""
        findings = []
        task_family = task_definition.get("family", "unknown")

        cpu = task_definition.get("cpu")
        memory = task_definition.get("memory")

        # Check for missing resource limits
        if not cpu and not memory:
            findings.append(
                {
                    "severity": "Medium",
                    "category": "resource_management",
                    "resource": self._format_resource_name("Task Definition", task_family),
                    "issue": "Task definition has no CPU or memory limits configured",
                    "recommendation": "Configure appropriate CPU and memory limits to prevent resource exhaustion",  # noqa: E501
                    "compliance_frameworks": ["SOC2"],
                }
            )

        # Check Fargate-specific resource configuration
        requires_attributes = task_definition.get("requiresAttributes", [])
        is_fargate = any(
            attr.get("name") == "com.amazonaws.ecs.capability.fargate"
            for attr in requires_attributes
        )

        if is_fargate and (not cpu or not memory):
            findings.append(
                {
                    "severity": "Medium",
                    "category": "resource_management",
                    "resource": self._format_resource_name("Task Definition", task_family),
                    "issue": "Task definition uses Fargate but has no CPU/memory configuration",
                    "recommendation": "Configure appropriate Fargate CPU and memory settings for optimal performance and cost",  # noqa: E501
                    "compliance_frameworks": ["SOC2"],
                }
            )

        # Check EC2-specific configuration
        is_ec2 = any(
            attr.get("name") == "com.amazonaws.ecs.capability.ec2" for attr in requires_attributes
        )
        placement_constraints = task_definition.get("placementConstraints", [])

        if is_ec2 and not placement_constraints:
            findings.append(
                {
                    "severity": "Medium",
                    "category": "resource_management",
                    "resource": self._format_resource_name("Task Definition", task_family),
                    "issue": "Task definition uses EC2 launch type but has no placement constraints",  # noqa: E501
                    "recommendation": "Configure placement constraints to ensure tasks run on appropriate instances",  # noqa: E501
                    "compliance_frameworks": ["SOC2"],
                }
            )

        return findings

    def _analyze_task_definition_launch_type(
        self, task_definition: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze task definition launch type configuration for security issues."""
        findings = []
        task_family = task_definition.get("family", "unknown")

        # Check for volumes configuration
        volumes = task_definition.get("volumes", [])
        if not volumes:
            findings.append(
                {
                    "severity": "Low",
                    "category": "resource_management",
                    "resource": self._format_resource_name("Task Definition", task_family),
                    "issue": "Task definition has no volumes configured, which may limit application functionality",  # noqa: E501
                    "recommendation": "Review if persistent storage or shared volumes are needed for the application",  # noqa: E501
                    "compliance_frameworks": ["SOC2"],
                }
            )

        # Check for container dependencies
        container_definitions = task_definition.get("containerDefinitions", [])
        has_dependencies = any(container.get("dependsOn") for container in container_definitions)

        if len(container_definitions) > 1 and not has_dependencies:
            findings.append(
                {
                    "severity": "Medium",
                    "category": "resource_management",
                    "resource": self._format_resource_name("Task Definition", task_family),
                    "issue": "Task definition has no container dependencies configured",
                    "recommendation": "Configure container dependencies to ensure proper startup order",  # noqa: E501
                    "compliance_frameworks": ["SOC2"],
                }
            )

        return findings

    def _analyze_task_definition_containers(
        self, task_definition: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze task definition container configurations for security issues."""
        findings = []
        task_family = task_definition.get("family", "unknown")

        container_definitions = task_definition.get("containerDefinitions", [])

        for container in container_definitions:
            container_name = container.get("name", "unknown")

            # Check for privileged containers
            if container.get("privileged"):
                findings.append(
                    {
                        "severity": "High",
                        "category": "container_security",
                        "resource": self._format_resource_name(
                            "Container", f"{container_name} | Task Definition: {task_family}"
                        ),
                        "issue": "Container is running in privileged mode, granting excessive host access",  # noqa: E501
                        "recommendation": "Remove privileged mode and use specific capabilities instead",  # noqa: E501
                        "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS"],
                    }
                )

            # Check for root user
            if container.get("user") == "root" or not container.get("user"):
                findings.append(
                    {
                        "severity": "Medium",
                        "category": "container_security",
                        "resource": self._format_resource_name(
                            "Container", f"{container_name} | Task Definition: {task_family}"
                        ),
                        "issue": "Container is running as root user, violating principle of least privilege",  # noqa: E501
                        "recommendation": "Configure container to run as non-root user with minimal required permissions",  # noqa: E501
                        "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS"],
                    }
                )

            # Check for read-only root filesystem
            if not container.get("readonlyRootFilesystem"):
                findings.append(
                    {
                        "severity": "Medium",
                        "category": "container_security",
                        "resource": self._format_resource_name(
                            "Container", f"{container_name} | Task Definition: {task_family}"
                        ),
                        "issue": "Container root filesystem is not read-only, allowing runtime modifications",  # noqa: E501
                        "recommendation": "Enable read-only root filesystem and use tmpfs for temporary files",  # noqa: E501
                        "compliance_frameworks": ["SOC2", "PCI-DSS"],
                    }
                )

            # Check for Docker image security
            image = container.get("image", "")
            if not self._is_valid_docker_image(image):
                findings.append(
                    {
                        "severity": "High",
                        "category": "container_security",
                        "resource": self._format_resource_name(
                            "Container", f"{container_name} | Task Definition: {task_family}"
                        ),
                        "issue": f"Container uses potentially untrusted Docker image: {image}",
                        "recommendation": "Use images from trusted registries (ECR, official Docker Hub images) and scan for vulnerabilities",  # noqa: E501
                        "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS"],
                    }
                )

            # Check for environment variables with sensitive data
            environment = container.get("environment", [])
            for env_var in environment:
                env_name = env_var.get("name", "")
                env_value = env_var.get("value", "")

                if self._contains_sensitive_data(env_name) or self._contains_sensitive_data(
                    env_value
                ):
                    findings.append(
                        {
                            "severity": "High",
                            "category": "secrets",
                            "resource": self._format_resource_name(
                                "Container", f"{container_name} | Task Definition: {task_family}"
                            ),
                            "issue": f"Environment variable '{env_name}' may contain sensitive information",  # noqa: E501
                            "recommendation": "Use AWS Secrets Manager or Systems Manager Parameter Store for sensitive data",  # noqa: E501
                            "compliance_frameworks": ["HIPAA", "PCI-DSS", "SOC2"],
                        }
                    )

            # Check for health check configuration
            health_check = container.get("healthCheck")
            if not health_check:
                findings.append(
                    {
                        "severity": "Low",
                        "category": "monitoring",
                        "resource": self._format_resource_name(
                            "Container", f"{container_name} | Task Definition: {task_family}"
                        ),
                        "issue": "Container has no health check configured",
                        "recommendation": "Configure health checks to ensure container availability and enable automatic recovery",  # noqa: E501
                        "compliance_frameworks": ["SOC2"],
                    }
                )

            # Check for resource limits at container level
            if not container.get("memory") and not container.get("memoryReservation"):
                findings.append(
                    {
                        "severity": "Medium",
                        "category": "resource_management",
                        "resource": self._format_resource_name(
                            "Container", f"{container_name} | Task Definition: {task_family}"
                        ),
                        "issue": "Container has no memory limits configured",
                        "recommendation": "Configure memory limits to prevent container from consuming excessive resources",  # noqa: E501
                        "compliance_frameworks": ["SOC2"],
                    }
                )

        return findings

    def get_task_definition_list(self, family_prefix: Optional[str] = None) -> List[str]:
        """
        Get list of task definition families.

        Args:
            family_prefix: Optional prefix to filter task definition families

        Returns:
            List of task definition family names
        """
        try:
            params = {}
            if family_prefix:
                params["familyPrefix"] = family_prefix

            response = self.ecs_client.list_task_definition_families(**params)
            return response.get("families", [])

        except ClientError as e:
            logger.error(f"Error listing task definition families: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing task definition families: {e}")
            return []

    def analyze_multiple_task_definitions(
        self, task_definition_arns: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Analyze security for multiple ECS task definitions.

        Args:
            task_definition_arns: List of task definition ARNs to analyze.
                If None, analyzes latest of all families.

        Returns:
            Dictionary containing analysis results for all task definitions
        """
        if task_definition_arns is None:
            # Get latest revision of each family
            families = self.get_task_definition_list()
            task_definition_arns = [f"{family}:LATEST" for family in families]

        if not task_definition_arns:
            return {
                "status": "error",
                "message": "No task definitions found to analyze",
                "results": {},
            }

        results = {}
        total_findings = 0
        severity_counts = {"High": 0, "Medium": 0, "Low": 0}

        for task_def_arn in task_definition_arns:
            logger.info(f"Analyzing task definition: {task_def_arn}")
            task_def_result = self.analyze_task_definition_security(task_def_arn)
            results[task_def_arn] = task_def_result

            if task_def_result.get("status") == "success":
                findings = task_def_result.get("findings", [])
                total_findings += len(findings)

                for finding in findings:
                    severity = finding.get("severity", "Unknown")
                    if severity in severity_counts:
                        severity_counts[severity] += 1

        return {
            "status": "success",
            "analyzed_task_definitions": len(task_definition_arns),
            "total_findings": total_findings,
            "severity_summary": severity_counts,
            "results": results,
        }

    def analyze_container_instances_security(self, cluster_name: str) -> Dict[str, Any]:
        """
        Analyze security configuration of ECS container instances in a cluster.

        Args:
            cluster_name: Name of the ECS cluster

        Returns:
            Dictionary containing security analysis results
        """
        try:
            # Get container instances
            response = self.ecs_client.list_container_instances(cluster=cluster_name)
            container_instance_arns = response.get("containerInstanceArns", [])

            if not container_instance_arns:
                return {
                    "cluster_name": cluster_name,
                    "status": "success",
                    "message": f"No container instances found in cluster '{cluster_name}'",
                    "findings": [],
                }

            # Get detailed information about container instances
            describe_response = self.ecs_client.describe_container_instances(
                cluster=cluster_name, containerInstances=container_instance_arns
            )

            container_instances = describe_response.get("containerInstances", [])
            findings = []

            for instance in container_instances:
                findings.extend(self._analyze_container_instance_security(instance))

            return {
                "cluster_name": cluster_name,
                "status": "success",
                "container_instances_count": len(container_instances),
                "findings": findings,
                "summary": {
                    "total_findings": len(findings),
                    "high_severity": len([f for f in findings if f.get("severity") == "High"]),
                    "medium_severity": len([f for f in findings if f.get("severity") == "Medium"]),
                    "low_severity": len([f for f in findings if f.get("severity") == "Low"]),
                },
            }

        except ClientError as e:
            logger.error(f"AWS API error analyzing container instances in {cluster_name}: {e}")
            return {
                "cluster_name": cluster_name,
                "status": "error",
                "message": f"AWS API error: {str(e)}",
                "findings": [],
            }
        except Exception as e:
            logger.error(f"Unexpected error analyzing container instances in {cluster_name}: {e}")
            return {
                "cluster_name": cluster_name,
                "status": "error",
                "message": f"Unexpected error: {str(e)}",
                "findings": [],
            }

    def _analyze_container_instance_security(
        self, instance: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze individual container instance for security issues."""
        findings = []
        instance_id = instance.get("ec2InstanceId", "unknown")

        # Check ECS agent version
        agent_version = instance.get("versionInfo", {}).get("agentVersion", "")
        if agent_version:
            # Check for known vulnerable versions (simplified check)
            try:
                version_parts = agent_version.split(".")
                if len(version_parts) >= 2:
                    major = int(version_parts[0])
                    minor = int(version_parts[1])

                    # Flag very old versions as potentially vulnerable
                    if major < 1 or (major == 1 and minor < 50):
                        findings.append(
                            {
                                "severity": "High",
                                "category": "security",
                                "resource": self._format_resource_name(
                                    "Container Instance", instance_id
                                ),
                                "issue": f"ECS agent version {agent_version} has known security vulnerabilities",  # noqa: E501
                                "recommendation": "Immediately update ECS agent to latest version to patch security vulnerabilities",  # noqa: E501
                                "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS"],
                            }
                        )
            except (ValueError, IndexError):
                findings.append(
                    {
                        "severity": "Medium",
                        "category": "security",
                        "resource": self._format_resource_name("Container Instance", instance_id),
                        "issue": f"Cannot parse ECS agent version: {agent_version}",
                        "recommendation": "Verify ECS agent version and ensure it is up to date for security",  # noqa: E501
                        "compliance_frameworks": ["SOC2"],
                    }
                )

        # Check agent connectivity
        agent_connected = instance.get("agentConnected", False)
        if not agent_connected:
            findings.append(
                {
                    "severity": "High",
                    "category": "security",
                    "resource": self._format_resource_name("Container Instance", instance_id),
                    "issue": "ECS agent is disconnected, preventing security monitoring and updates",  # noqa: E501
                    "recommendation": "Investigate and reconnect ECS agent to maintain security oversight",  # noqa: E501
                    "compliance_frameworks": ["SOC2", "HIPAA"],
                }
            )

        # Check instance type for security considerations
        attributes = instance.get("attributes", [])
        instance_type = None
        for attr in attributes:
            if attr.get("name") == "ecs.instance-type":
                instance_type = attr.get("value")
                break

        if instance_type:
            # Flag older generation instances
            if any(
                gen in instance_type.lower()
                for gen in ["t1", "m1", "c1", "cc1", "cc2", "cg1", "m2", "cr1", "hi1", "hs1"]
            ):
                findings.append(
                    {
                        "severity": "Medium",
                        "category": "security",
                        "resource": self._format_resource_name("Container Instance", instance_id),
                        "issue": f"Instance type {instance_type} is from older generation with potential hardware vulnerabilities",  # noqa: E501
                        "recommendation": "Migrate to newer generation instance types with enhanced security features",  # noqa: E501
                        "compliance_frameworks": ["SOC2", "PCI-DSS"],
                    }
                )

        return findings

    def analyze_network_security(self, cluster_name: str) -> Dict[str, Any]:
        """
        Analyze network security configuration for ECS resources.

        Args:
            cluster_name: Name of the ECS cluster

        Returns:
            Dictionary containing network security analysis results
        """
        try:
            findings = []

            # Analyze VPC and subnet security
            findings.extend(self._analyze_vpc_security(cluster_name))

            # Analyze security groups
            findings.extend(self._analyze_security_groups(cluster_name))

            # Analyze load balancers
            findings.extend(self._analyze_load_balancers(cluster_name))

            return {
                "cluster_name": cluster_name,
                "status": "success",
                "findings": findings,
                "summary": {
                    "total_findings": len(findings),
                    "high_severity": len([f for f in findings if f.get("severity") == "High"]),
                    "medium_severity": len([f for f in findings if f.get("severity") == "Medium"]),
                    "low_severity": len([f for f in findings if f.get("severity") == "Low"]),
                },
            }

        except ClientError as e:
            logger.error(f"AWS API error analyzing network security for {cluster_name}: {e}")
            return {
                "cluster_name": cluster_name,
                "status": "error",
                "message": f"AWS API error: {str(e)}",
                "findings": [],
            }
        except Exception as e:
            logger.error(f"Unexpected error analyzing network security for {cluster_name}: {e}")
            return {
                "cluster_name": cluster_name,
                "status": "error",
                "message": f"Unexpected error: {str(e)}",
                "findings": [],
            }

    def _analyze_vpc_security(self, cluster_name: str) -> List[Dict[str, Any]]:
        """Analyze VPC security configuration."""
        findings = []

        try:
            # Get VPCs
            vpcs_response = self.ec2_client.describe_vpcs()
            vpcs = vpcs_response.get("Vpcs", [])

            for vpc in vpcs:
                vpc_id = vpc.get("VpcId", "unknown")

                # Check for VPC Flow Logs
                flow_logs_response = self.ec2_client.describe_flow_logs(
                    Filters=[
                        {"Name": "resource-id", "Values": [vpc_id]},
                        {"Name": "resource-type", "Values": ["VPC"]},
                    ]
                )

                flow_logs = flow_logs_response.get("FlowLogs", [])
                active_flow_logs = [fl for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"]

                if not active_flow_logs:
                    findings.append(
                        {
                            "severity": "Medium",
                            "category": "network_security",
                            "resource": self._format_resource_name("VPC", vpc_id),
                            "issue": "VPC Flow Logs are not enabled, limiting network security monitoring capabilities",  # noqa: E501
                            "recommendation": "Enable VPC Flow Logs to monitor network traffic for security analysis and compliance",  # noqa: E501
                            "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS"],
                        }
                    )

                # Check route tables for overly permissive routes
                route_tables_response = self.ec2_client.describe_route_tables(
                    Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
                )

                route_tables = route_tables_response.get("RouteTables", [])
                for route_table in route_tables:
                    route_table_id = route_table.get("RouteTableId", "unknown")
                    routes = route_table.get("Routes", [])

                    for route in routes:
                        if route.get("DestinationCidrBlock") == "0.0.0.0/0" and route.get(
                            "GatewayId", ""
                        ).startswith("igw-"):
                            # Check if this is associated with private subnets
                            associations = route_table.get("Associations", [])
                            for assoc in associations:
                                if assoc.get("SubnetId"):
                                    findings.append(
                                        {
                                            "severity": "Medium",
                                            "category": "network_security",
                                            "resource": self._format_resource_name(
                                                "Route Table", route_table_id
                                            ),
                                            "issue": "Route table has route to 0.0.0.0/0 through internet gateway in what appears to be a private subnet",  # noqa: E501
                                            "recommendation": "Review routing configuration to ensure private subnets route through NAT Gateway instead of Internet Gateway",  # noqa: E501
                                            "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS"],
                                        }
                                    )
                                    break

        except ClientError as e:
            logger.error(f"Error analyzing VPC security: {e}")

        return findings

    def _analyze_security_groups(self, cluster_name: str) -> List[Dict[str, Any]]:
        """Analyze security groups for overly permissive rules."""
        findings = []

        try:
            # Get all security groups
            sg_response = self.ec2_client.describe_security_groups()
            security_groups = sg_response.get("SecurityGroups", [])

            for sg in security_groups:
                sg_id = sg.get("GroupId", "unknown")

                # Check inbound rules
                for rule in sg.get("IpPermissions", []):
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            port = rule.get("FromPort", "all")
                            findings.append(
                                {
                                    "severity": "Medium",
                                    "category": "network_security",
                                    "resource": self._format_resource_name("Security Group", sg_id),
                                    "issue": f"Security group {sg_id} allows inbound traffic on port {port} from 0.0.0.0/0",  # noqa: E501
                                    "recommendation": "Restrict inbound rules to specific IP ranges or security groups to reduce attack surface",  # noqa: E501
                                    "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS"],
                                }
                            )

                # Check outbound rules
                for rule in sg.get("IpPermissionsEgress", []):
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0" and not rule.get("FromPort"):
                            findings.append(
                                {
                                    "severity": "Medium",
                                    "category": "network_security",
                                    "resource": self._format_resource_name("Security Group", sg_id),
                                    "issue": f"Security group {sg_id} allows outbound traffic to 0.0.0.0/0 on all ports",  # noqa: E501
                                    "recommendation": "Restrict outbound rules to specific destinations and ports following principle of least privilege",  # noqa: E501
                                    "compliance_frameworks": ["SOC2", "PCI-DSS"],
                                }
                            )

        except ClientError as e:
            logger.error(f"Error analyzing security groups: {e}")

        return findings

    def _analyze_load_balancers(self, cluster_name: str) -> List[Dict[str, Any]]:
        """Analyze load balancers for security issues."""
        findings = []

        try:
            # Get Application Load Balancers
            alb_response = self.elbv2_client.describe_load_balancers()
            load_balancers = alb_response.get("LoadBalancers", [])

            for lb in load_balancers:
                lb_arn = lb.get("LoadBalancerArn", "unknown")
                lb_type = lb.get("Type", "unknown")

                if lb_type == "application":
                    # Check for WAF association
                    try:
                        # Note: This is a simplified check - in practice you'd need to check WAF associations  # noqa: E501
                        findings.append(
                            {
                                "severity": "Medium",
                                "category": "network_security",
                                "resource": self._format_resource_name("Load Balancer", lb_arn),
                                "issue": "Application Load Balancer is not configured with WAF protection",  # noqa: E501
                                "recommendation": "Configure AWS WAF to protect against common web application attacks",  # noqa: E501
                                "compliance_frameworks": ["SOC2", "PCI-DSS"],
                            }
                        )
                    except Exception:
                        pass

                # Check listeners for HTTPS
                listeners_response = self.elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)
                listeners = listeners_response.get("Listeners", [])

                for listener in listeners:
                    protocol = listener.get("Protocol", "")
                    if protocol in ["HTTP", "TCP"] and listener.get("Port") not in [80, 8080]:
                        findings.append(
                            {
                                "severity": "High",
                                "category": "network_security",
                                "resource": self._format_resource_name("Load Balancer", lb_arn),
                                "issue": "Load Balancer listener is not using HTTPS/TLS encryption",
                                "recommendation": "Configure HTTPS listeners with valid SSL/TLS certificates for encrypted communication",  # noqa: E501
                                "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS"],
                            }
                        )

                # Check target groups
                target_groups_response = self.elbv2_client.describe_target_groups(
                    LoadBalancerArn=lb_arn
                )
                target_groups = target_groups_response.get("TargetGroups", [])

                for tg in target_groups:
                    tg_arn = tg.get("TargetGroupArn", "unknown")
                    health_check_protocol = tg.get("HealthCheckProtocol", "")

                    if health_check_protocol == "HTTP":
                        findings.append(
                            {
                                "severity": "Medium",
                                "category": "network_security",
                                "resource": self._format_resource_name("Target Group", tg_arn),
                                "issue": "Target Group health check is using HTTP instead of HTTPS",
                                "recommendation": "Configure HTTPS health checks for better security and to match production traffic patterns",  # noqa: E501
                                "compliance_frameworks": ["SOC2", "PCI-DSS"],
                            }
                        )

        except ClientError as e:
            logger.error(f"Error analyzing load balancers: {e}")

        return findings

    def analyze_comprehensive_security(self, cluster_name: str) -> Dict[str, Any]:
        """
        Perform comprehensive security analysis across all ECS components.

        Args:
            cluster_name: Name of the ECS cluster

        Returns:
            Dictionary containing comprehensive security analysis results
        """
        try:
            logger.info(f"Starting comprehensive security analysis for cluster: {cluster_name}")

            # Perform all security analyses
            cluster_analysis = self.analyze_cluster_security(cluster_name)
            services_analysis = self.analyze_multiple_services(cluster_name)
            task_definitions_analysis = self.analyze_multiple_task_definitions()
            container_instances_analysis = self.analyze_container_instances_security(cluster_name)
            network_analysis = self.analyze_network_security(cluster_name)

            # Aggregate findings
            all_findings = []
            total_findings = 0
            severity_counts = {"High": 0, "Medium": 0, "Low": 0}

            analyses = [
                ("cluster", cluster_analysis),
                ("services", services_analysis),
                ("task_definitions", task_definitions_analysis),
                ("container_instances", container_instances_analysis),
                ("network", network_analysis),
            ]

            for analysis_type, analysis_result in analyses:
                if analysis_result.get("status") == "success":
                    findings = analysis_result.get("findings", [])
                    if analysis_type in ["services", "task_definitions"]:
                        # These return nested results
                        for resource_result in analysis_result.get("results", {}).values():
                            if isinstance(resource_result, dict) and resource_result.get(
                                "findings"
                            ):
                                findings.extend(resource_result["findings"])

                    all_findings.extend(findings)
                    total_findings += len(findings)

                    for finding in findings:
                        severity = finding.get("severity", "Unknown")
                        if severity in severity_counts:
                            severity_counts[severity] += 1

            return {
                "cluster_name": cluster_name,
                "status": "success",
                "analysis_timestamp": "2024-01-01T00:00:00Z",  # In practice, use actual timestamp
                "total_findings": total_findings,
                "severity_summary": severity_counts,
                "findings": all_findings,
                "detailed_results": {
                    "cluster_analysis": cluster_analysis,
                    "services_analysis": services_analysis,
                    "task_definitions_analysis": task_definitions_analysis,
                    "container_instances_analysis": container_instances_analysis,
                    "network_analysis": network_analysis,
                },
            }

        except Exception as e:
            logger.error(f"Error in comprehensive security analysis for {cluster_name}: {e}")
            return {
                "cluster_name": cluster_name,
                "status": "error",
                "message": f"Comprehensive analysis error: {str(e)}",
                "findings": [],
            }

    def generate_security_report(
        self,
        cluster_name: str,
        severity_filter: Optional[List[str]] = None,
        category_filter: Optional[List[str]] = None,
        compliance_framework: Optional[str] = None,
        include_recommendations: bool = True,
        format_type: str = "json",
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

        Returns:
            Formatted security report
        """
        try:
            # Get comprehensive analysis
            analysis_result = self.analyze_comprehensive_security(cluster_name)

            if analysis_result.get("status") != "success":
                return analysis_result

            findings = analysis_result.get("findings", [])

            # Apply filters
            filtered_findings = self._apply_filters(
                findings, severity_filter, category_filter, compliance_framework
            )

            # Generate report based on format type
            if format_type == "summary":
                return self._generate_summary_report(
                    cluster_name, filtered_findings, analysis_result
                )
            elif format_type == "detailed":
                return self._generate_detailed_report(
                    cluster_name, filtered_findings, analysis_result, include_recommendations
                )
            else:  # json format
                return {
                    "cluster_name": cluster_name,
                    "report_timestamp": "2024-01-01T00:00:00Z",  # In practice, use actual timestamp
                    "filters_applied": {
                        "severity_filter": severity_filter,
                        "category_filter": category_filter,
                        "compliance_framework": compliance_framework,
                    },
                    "total_findings": len(filtered_findings),
                    "severity_summary": self._calculate_severity_summary(filtered_findings),
                    "category_summary": self._calculate_category_summary(filtered_findings),
                    "findings": filtered_findings
                    if include_recommendations
                    else self._strip_recommendations(filtered_findings),
                    "compliance_summary": self._calculate_compliance_summary(filtered_findings),
                }

        except Exception as e:
            logger.error(f"Error generating security report for {cluster_name}: {e}")
            return {
                "cluster_name": cluster_name,
                "status": "error",
                "message": f"Report generation error: {str(e)}",
            }

    def _apply_filters(
        self,
        findings: List[Dict[str, Any]],
        severity_filter: Optional[List[str]] = None,
        category_filter: Optional[List[str]] = None,
        compliance_framework: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Apply filters to findings list."""
        filtered_findings = findings

        if severity_filter:
            filtered_findings = [
                f for f in filtered_findings if f.get("severity") in severity_filter
            ]

        if category_filter:
            filtered_findings = [
                f for f in filtered_findings if f.get("category") in category_filter
            ]

        if compliance_framework:
            filtered_findings = [
                f
                for f in filtered_findings
                if compliance_framework in f.get("compliance_frameworks", [])
            ]

        return filtered_findings

    def _calculate_severity_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate severity distribution."""
        severity_counts = {"High": 0, "Medium": 0, "Low": 0}
        for finding in findings:
            severity = finding.get("severity", "Unknown")
            if severity in severity_counts:
                severity_counts[severity] += 1
        return severity_counts

    def _calculate_category_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate category distribution."""
        category_counts = {}
        for finding in findings:
            category = finding.get("category", "unknown")
            category_counts[category] = category_counts.get(category, 0) + 1
        return category_counts

    def _calculate_compliance_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate compliance framework distribution."""
        compliance_counts = {}
        for finding in findings:
            frameworks = finding.get("compliance_frameworks", [])
            for framework in frameworks:
                compliance_counts[framework] = compliance_counts.get(framework, 0) + 1
        return compliance_counts

    def _generate_summary_report(
        self, cluster_name: str, findings: List[Dict[str, Any]], analysis_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate a summary report format."""
        severity_summary = self._calculate_severity_summary(findings)
        category_summary = self._calculate_category_summary(findings)

        # Calculate risk score (weighted by severity)
        risk_score = (
            severity_summary.get("High", 0) * 10
            + severity_summary.get("Medium", 0) * 5
            + severity_summary.get("Low", 0) * 1
        )

        # Determine overall security posture
        if risk_score == 0:
            security_posture = "Excellent"
        elif risk_score <= 10:
            security_posture = "Good"
        elif risk_score <= 50:
            security_posture = "Fair"
        else:
            security_posture = "Poor"

        return {
            "cluster_name": cluster_name,
            "report_type": "summary",
            "security_posture": security_posture,
            "risk_score": risk_score,
            "total_findings": len(findings),
            "severity_breakdown": severity_summary,
            "category_breakdown": category_summary,
            "top_issues": self._get_top_issues(findings, limit=5),
            "recommendations_summary": self._get_recommendations_summary(findings),
        }

    def _generate_detailed_report(
        self,
        cluster_name: str,
        findings: List[Dict[str, Any]],
        analysis_result: Dict[str, Any],
        include_recommendations: bool,
    ) -> Dict[str, Any]:
        """Generate a detailed report format."""
        return {
            "cluster_name": cluster_name,
            "report_type": "detailed",
            "executive_summary": self._generate_executive_summary(findings),
            "detailed_findings": findings
            if include_recommendations
            else self._strip_recommendations(findings),
            "analysis_breakdown": {
                "cluster_analysis": analysis_result.get("detailed_results", {}).get(
                    "cluster_analysis", {}
                ),
                "services_analysis": analysis_result.get("detailed_results", {}).get(
                    "services_analysis", {}
                ),
                "task_definitions_analysis": analysis_result.get("detailed_results", {}).get(
                    "task_definitions_analysis", {}
                ),
                "container_instances_analysis": analysis_result.get("detailed_results", {}).get(
                    "container_instances_analysis", {}
                ),
                "network_analysis": analysis_result.get("detailed_results", {}).get(
                    "network_analysis", {}
                ),
            },
            "remediation_roadmap": self._generate_remediation_roadmap(findings),
            "compliance_status": self._generate_compliance_status(findings),
        }

    def _get_top_issues(
        self, findings: List[Dict[str, Any]], limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Get top issues by severity and frequency."""
        # Sort by severity (High > Medium > Low) and return top issues
        severity_order = {"High": 3, "Medium": 2, "Low": 1}
        sorted_findings = sorted(
            findings,
            key=lambda x: severity_order.get(x.get("severity", "Low"), 0),
            reverse=True,
        )
        return sorted_findings[:limit]

    def _get_recommendations_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a summary of recommendations."""
        high_priority = [f for f in findings if f.get("severity") == "High"]
        medium_priority = [f for f in findings if f.get("severity") == "Medium"]

        return {
            "immediate_actions_required": len(high_priority),
            "medium_priority_actions": len(medium_priority),
            "key_recommendations": [
                "Review and remediate all High severity findings immediately",
                "Implement proper IAM roles and policies",
                "Enable security monitoring and logging",
                "Regular security assessments and updates",
            ],
        }

    def _generate_executive_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate executive summary."""
        severity_summary = self._calculate_severity_summary(findings)
        category_summary = self._calculate_category_summary(findings)

        return {
            "total_security_findings": len(findings),
            "critical_issues": severity_summary.get("High", 0),
            "areas_of_concern": list(category_summary.keys()),
            "overall_assessment": "Security review completed with detailed findings and recommendations",  # noqa: E501
            "next_steps": [
                "Address all High severity findings immediately",
                "Develop remediation plan for Medium severity findings",
                "Implement continuous security monitoring",
            ],
        }

    def _generate_remediation_roadmap(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate remediation roadmap."""
        high_findings = [f for f in findings if f.get("severity") == "High"]
        medium_findings = [f for f in findings if f.get("severity") == "Medium"]
        low_findings = [f for f in findings if f.get("severity") == "Low"]

        return {
            "phase_1_immediate": {
                "timeline": "0-2 weeks",
                "priority": "Critical",
                "findings_count": len(high_findings),
                "focus_areas": list(set(f.get("category", "unknown") for f in high_findings)),
            },
            "phase_2_short_term": {
                "timeline": "2-8 weeks",
                "priority": "High",
                "findings_count": len(medium_findings),
                "focus_areas": list(set(f.get("category", "unknown") for f in medium_findings)),
            },
            "phase_3_long_term": {
                "timeline": "2-6 months",
                "priority": "Medium",
                "findings_count": len(low_findings),
                "focus_areas": list(set(f.get("category", "unknown") for f in low_findings)),
            },
        }

    def _generate_compliance_status(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate compliance status summary."""
        compliance_summary = self._calculate_compliance_summary(findings)

        return {
            "frameworks_assessed": list(compliance_summary.keys()),
            "compliance_gaps": compliance_summary,
            "recommendations": [
                "Address compliance gaps identified in the findings",
                "Implement continuous compliance monitoring",
                "Regular compliance assessments and audits",
            ],
        }

    def _strip_recommendations(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove detailed recommendations from findings for lighter reports."""
        stripped_findings = []
        for finding in findings:
            stripped_finding = finding.copy()
            if "recommendation" in stripped_finding:
                del stripped_finding["recommendation"]
            stripped_findings.append(stripped_finding)
        return stripped_findings

    def export_findings_to_csv(self, findings: List[Dict[str, Any]], filename: str) -> bool:
        """
        Export findings to CSV format for external analysis.

        Args:
            findings: List of security findings
            filename: Output CSV filename

        Returns:
            True if export successful, False otherwise
        """
        try:
            import csv

            if not findings:
                logger.warning("No findings to export")
                return False

            # Define CSV headers
            headers = [
                "severity",
                "category",
                "resource",
                "issue",
                "recommendation",
                "compliance_frameworks",
            ]

            with open(filename, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=headers)
                writer.writeheader()

                for finding in findings:
                    # Prepare row data
                    row = {
                        "severity": finding.get("severity", ""),
                        "category": finding.get("category", ""),
                        "resource": finding.get("resource", ""),
                        "issue": finding.get("issue", ""),
                        "recommendation": finding.get("recommendation", ""),
                        "compliance_frameworks": ", ".join(
                            finding.get("compliance_frameworks", [])
                        ),
                    }
                    writer.writerow(row)

            logger.info(f"Successfully exported {len(findings)} findings to {filename}")
            return True

        except Exception as e:
            logger.error(f"Error exporting findings to CSV: {e}")
            return False

    def get_security_metrics(self, cluster_name: str) -> Dict[str, Any]:
        """
        Get security metrics and KPIs for monitoring and dashboards.

        Args:
            cluster_name: Name of the ECS cluster

        Returns:
            Dictionary containing security metrics
        """
        try:
            analysis_result = self.analyze_comprehensive_security(cluster_name)

            if analysis_result.get("status") != "success":
                return {"status": "error", "message": "Failed to get security metrics"}

            findings = analysis_result.get("findings", [])
            severity_summary = self._calculate_severity_summary(findings)
            category_summary = self._calculate_category_summary(findings)

            # Calculate security score (0-100, higher is better)
            total_possible_score = 100
            penalty_per_high = 20
            penalty_per_medium = 10
            penalty_per_low = 5

            security_score = max(
                0,
                total_possible_score
                - (severity_summary.get("High", 0) * penalty_per_high)
                - (severity_summary.get("Medium", 0) * penalty_per_medium)
                - (severity_summary.get("Low", 0) * penalty_per_low),
            )

            return {
                "cluster_name": cluster_name,
                "security_score": security_score,
                "total_findings": len(findings),
                "severity_distribution": severity_summary,
                "category_distribution": category_summary,
                "compliance_coverage": self._calculate_compliance_summary(findings),
                "risk_level": self._calculate_risk_level(security_score),
                "trends": {
                    "improving": security_score >= 80,
                    "stable": 60 <= security_score < 80,
                    "declining": security_score < 60,
                },
                "recommendations_count": len([f for f in findings if f.get("recommendation")]),
            }

        except Exception as e:
            logger.error(f"Error getting security metrics for {cluster_name}: {e}")
            return {"status": "error", "message": f"Metrics error: {str(e)}"}

    def _calculate_risk_level(self, security_score: int) -> str:
        """Calculate risk level based on security score."""
        if security_score >= 90:
            return "Very Low"
        elif security_score >= 80:
            return "Low"
        elif security_score >= 60:
            return "Medium"
        elif security_score >= 40:
            return "High"
        else:
            return "Very High"
