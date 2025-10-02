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

"""Security Analysis API for ECS MCP Server.

This module provides comprehensive security analysis for ECS clusters.

Consolidated security analysis implementation that leverages existing MCP tools
for data collection while providing comprehensive security recommendations.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from typing import Literal  # noqa: F401
except ImportError:
    from typing_extensions import Literal  # noqa: F401

from awslabs.ecs_mcp_server.api.resource_management import ecs_api_operation
from awslabs.ecs_mcp_server.api.troubleshooting_tools.fetch_network_configuration import (
    fetch_network_configuration,
)
from awslabs.ecs_mcp_server.api.troubleshooting_tools.utils import (
    find_clusters,
    find_task_definitions,
)

logger = logging.getLogger(__name__)


class DataAdapter:
    """
    Adapter that uses existing MCP tools to collect data for security analysis.

    This class eliminates duplicate data collection by leveraging existing APIs
    and utilities already present in the ECS MCP server.
    """

    def __init__(self):
        """Initialize the DataAdapter."""
        self.logger = logger

    async def collect_cluster_data(
        self, cluster_name: str, region: str = "us-east-1"
    ) -> Dict[str, Any]:
        """Collect cluster data using existing resource management API."""
        try:
            self.logger.info(f"Collecting cluster data for {cluster_name}")

            # Get basic cluster information
            cluster_response = await ecs_api_operation(
                "DescribeClusters", {"clusters": [cluster_name]}
            )

            # Enhanced: Get capacity providers for security analysis
            capacity_providers_response = await ecs_api_operation(
                "DescribeCapacityProviders",
                {"capacityProviders": []},  # Gets all capacity providers
            )

            # Enhanced: Get cluster tags for compliance analysis
            # Note: We'll skip tags for now as we need the actual cluster ARN from the response
            tags_response = {"tags": []}

            if "error" in cluster_response:
                self.logger.error(f"Error collecting cluster data: {cluster_response['error']}")
                return {
                    "error": cluster_response["error"],
                    "cluster_name": cluster_name,
                    "region": region,
                }

            clusters = cluster_response.get("clusters", [])
            if not clusters:
                self.logger.warning(f"No cluster found with name: {cluster_name}")
                return {
                    "error": f"Cluster '{cluster_name}' not found",
                    "cluster_name": cluster_name,
                    "region": region,
                }

            cluster_data = clusters[0]

            # Enhanced cluster data with additional security-relevant information
            enhanced_cluster_data = {
                "cluster": cluster_data,
                "capacity_providers": capacity_providers_response.get("capacityProviders", [])
                if "error" not in capacity_providers_response
                else [],
                "tags": tags_response.get("tags", []) if "error" not in tags_response else [],
                "cluster_name": cluster_name,
                "region": region,
                "status": "success",
            }

            # Log any errors from enhanced data collection
            if "error" in capacity_providers_response:
                self.logger.warning(
                    f"Could not fetch capacity providers: {capacity_providers_response['error']}"
                )
            if "error" in tags_response:
                self.logger.warning(f"Could not fetch cluster tags: {tags_response['error']}")

            return enhanced_cluster_data

        except Exception as e:
            self.logger.error(f"Unexpected error collecting cluster data for {cluster_name}: {e}")
            return {"error": str(e), "cluster_name": cluster_name, "region": region}

    async def collect_service_data(
        self, cluster_name: str, service_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Collect service data using existing troubleshooting tools utilities."""
        try:
            self.logger.info(f"Collecting service data for cluster {cluster_name}")

            if service_name:
                service_names = [service_name]
            else:
                # Use direct ECS API call instead of find_services to avoid async iterator issues
                try:
                    list_services_response = await ecs_api_operation(
                        "ListServices", {"cluster": cluster_name}
                    )

                    if "error" in list_services_response:
                        self.logger.warning(
                            f"Error listing services: {list_services_response['error']}"
                        )
                        service_names = []
                    else:
                        service_arns = list_services_response.get("serviceArns", [])
                        # Extract service names from ARNs
                        service_names = []
                        for arn in service_arns:
                            # ARN: arn:aws:ecs:region:account:service/cluster-name/service-name
                            if "/" in arn:
                                service_name_from_arn = arn.split("/")[-1]
                                service_names.append(service_name_from_arn)
                except Exception as e:
                    self.logger.warning(f"Error listing services for cluster {cluster_name}: {e}")
                    service_names = []

            if not service_names:
                self.logger.warning(f"No services found in cluster: {cluster_name}")
                return {"services": [], "cluster_name": cluster_name, "status": "success"}

            services_data = []

            for svc_name in service_names:
                try:
                    service_response = await ecs_api_operation(
                        "DescribeServices", {"cluster": cluster_name, "services": [svc_name]}
                    )

                    if "error" in service_response:
                        self.logger.error(
                            f"Error getting service {svc_name}: {service_response['error']}"
                        )
                        continue

                    services = service_response.get("services", [])
                    if not services:
                        self.logger.warning(f"Service {svc_name} not found in response")
                        continue

                    service_info = services[0]

                    task_definitions = await find_task_definitions(
                        cluster_name=cluster_name, service_name=svc_name
                    )

                    task_definition = None
                    if task_definitions:
                        task_definition = task_definitions[0]
                    else:
                        task_def_arn = service_info.get("taskDefinition")
                        if task_def_arn:
                            task_def_response = await ecs_api_operation(
                                "DescribeTaskDefinition", {"taskDefinition": task_def_arn}
                            )
                            if "taskDefinition" in task_def_response:
                                task_definition = task_def_response["taskDefinition"]

                    # Enhanced: Get service tags for compliance analysis
                    service_arn = service_info.get("serviceArn", "")
                    service_tags_response = await ecs_api_operation(
                        "ListTagsForResource", {"resourceArn": service_arn}
                    )

                    # Enhanced: Get running tasks for runtime security analysis
                    tasks_response = await ecs_api_operation(
                        "ListTasks", {"cluster": cluster_name, "serviceName": svc_name}
                    )

                    service_data = {
                        "service": service_info,
                        "task_definition": task_definition,
                        "tags": service_tags_response.get("tags", [])
                        if "error" not in service_tags_response
                        else [],
                        "running_tasks": tasks_response.get("taskArns", [])
                        if "error" not in tasks_response
                        else [],
                    }

                    services_data.append(service_data)

                except Exception as e:
                    self.logger.error(f"Error collecting data for service {svc_name}: {e}")
                    continue

            return {"services": services_data, "cluster_name": cluster_name, "status": "success"}

        except Exception as e:
            self.logger.error(f"Unexpected error collecting service data for {cluster_name}: {e}")
            return {"error": str(e), "cluster_name": cluster_name, "services": []}

    async def collect_network_data(
        self, cluster_name: str, vpc_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Collect network data using existing fetch_network_configuration function."""
        try:
            self.logger.info(f"Collecting network data for cluster {cluster_name}")

            network_response = await fetch_network_configuration(
                cluster_name=cluster_name, vpc_id=vpc_id
            )

            if network_response.get("status") == "error":
                self.logger.error(f"Error collecting network data: {network_response.get('error')}")
                return {
                    "error": network_response.get("error"),
                    "cluster_name": cluster_name,
                    "network_data": {},
                }

            network_data = network_response.get("data", {})
            raw_resources = network_data.get("raw_resources", {})

            security_network_data = {
                "vpcs": raw_resources.get("vpcs", {}),
                "subnets": raw_resources.get("subnets", {}),
                "security_groups": raw_resources.get("security_groups", {}),
                "route_tables": raw_resources.get("route_tables", {}),
                "network_interfaces": raw_resources.get("network_interfaces", {}),
                "nat_gateways": raw_resources.get("nat_gateways", {}),
                "internet_gateways": raw_resources.get("internet_gateways", {}),
                "load_balancers": raw_resources.get("load_balancers", {}),
                "target_groups": raw_resources.get("target_groups", {}),
                "vpc_ids": network_data.get("vpc_ids", []),
                "timestamp": network_data.get("timestamp"),
            }

            return {
                "network_data": security_network_data,
                "cluster_name": cluster_name,
                "status": "success",
            }

        except Exception as e:
            self.logger.error(f"Unexpected error collecting network data for {cluster_name}: {e}")
            return {"error": str(e), "cluster_name": cluster_name, "network_data": {}}

    async def adapt_to_security_format(
        self, cluster_name: str, region: str = "us-east-1"
    ) -> Dict[str, Any]:
        """Adapt collected data to security analysis format."""
        try:
            cluster_data = await self.collect_cluster_data(cluster_name, region)
            service_data = await self.collect_service_data(cluster_name)
            network_data = await self.collect_network_data(cluster_name)

            errors = []
            if "error" in cluster_data:
                errors.append(f"Cluster data: {cluster_data['error']}")
            if "error" in service_data:
                errors.append(f"Service data: {service_data['error']}")
            if "error" in network_data:
                errors.append(f"Network data: {network_data['error']}")

            security_format = {
                region: {
                    "clusters": {
                        cluster_name: {
                            "cluster": cluster_data.get("cluster", {}),
                            "capacity_providers": cluster_data.get("capacity_providers", []),
                            "cluster_tags": cluster_data.get("tags", []),
                            "services": service_data.get("services", []),
                            "network_data": network_data.get("network_data", {}),
                            "region_info": {"name": region},
                        }
                    }
                }
            }

            if errors:
                security_format[region]["clusters"][cluster_name]["errors"] = errors
                self.logger.warning(f"Data collection completed with errors: {errors}")

            return security_format

        except Exception as e:
            self.logger.error(f"Error adapting data to security format: {e}")
            return {region: {"error": str(e), "cluster_name": cluster_name, "region": region}}


class SecurityAnalyzer:
    """Basic ECS security analyzer following AWS best practices."""

    def __init__(self):
        """Initialize the SecurityAnalyzer."""
        self.logger = logger

    def analyze(self, ecs_data: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive security analysis of ECS configurations."""
        recommendations = []

        for region, region_data in ecs_data.items():
            if "error" in region_data:
                continue

            for cluster_name, cluster_data in region_data.get("clusters", {}).items():
                if "error" in cluster_data:
                    continue

                # Analyze cluster-level security
                recommendations.extend(
                    self._analyze_cluster_security(cluster_name, cluster_data, region)
                )

                # Analyze service-level security
                services = cluster_data.get("services", [])
                for service_data in services:
                    service = service_data.get("service", {})
                    service_name = service.get("serviceName", "unknown")

                    service_recommendations = self._analyze_service_security(
                        service, service_name, cluster_name, region
                    )
                    recommendations.extend(service_recommendations)

                    # Analyze task definition security
                    task_def = service_data.get("task_definition", {})
                    if task_def:
                        task_def_recommendations = self._analyze_task_definition_security(
                            task_def, service_name, cluster_name, region
                        )
                        recommendations.extend(task_def_recommendations)

                # Analyze network security
                network_data = cluster_data.get("network", {})
                if network_data:
                    network_recommendations = self._analyze_network_infrastructure(
                        network_data, cluster_name, region
                    )
                    recommendations.extend(network_recommendations)

        return {
            "recommendations": recommendations,
            "total_issues": len(recommendations),
            "analysis_summary": self._generate_analysis_summary(recommendations),
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _analyze_cluster_security(
        self, cluster_name: str, cluster_data: Dict[str, Any], region: str
    ) -> List[Dict[str, Any]]:
        """Analyze cluster-level security configurations."""
        recommendations = []

        cluster_info = cluster_data.get("cluster", {})
        cluster_settings = cluster_info.get("settings", [])

        # Check Container Insights
        container_insights_enabled = any(
            setting.get("name") == "containerInsights" and setting.get("value") == "enabled"
            for setting in cluster_settings
        )

        if not container_insights_enabled:
            recommendations.append(
                {
                    "title": "Enable Container Insights for Security Monitoring",
                    "severity": "Medium",
                    "category": "monitoring",
                    "resource": f"Cluster: {cluster_name}",
                    "issue": (
                        "Container Insights monitoring is disabled, reducing visibility into "
                        "container performance and security"
                    ),
                    "recommendation": (
                        "Enable Container Insights for comprehensive monitoring and "
                        "security observability"
                    ),
                }
            )

        # Check cluster configuration
        configuration = cluster_info.get("configuration", {})

        # Check execute command configuration
        execute_command_config = configuration.get("executeCommandConfiguration", {})
        if not execute_command_config:
            recommendations.append(
                {
                    "title": "Configure Execute Command Security",
                    "severity": "Medium",
                    "category": "security",
                    "resource": f"Cluster: {cluster_name}",
                    "issue": (
                        "Execute command configuration is not set up, missing audit "
                        "and logging capabilities"
                    ),
                    "recommendation": (
                        "Configure execute command with proper logging and KMS encryption "
                        "for security auditing"
                    ),
                }
            )
        else:
            # Check logging configuration
            logging_config = execute_command_config.get("logging")
            if logging_config != "OVERRIDE":
                recommendations.append(
                    {
                        "title": "Enable Execute Command Audit Logging",
                        "severity": "Medium",
                        "category": "monitoring",
                        "resource": f"Cluster: {cluster_name}",
                        "issue": "Execute command audit logging is not properly configured",
                        "recommendation": (
                            "Enable CloudWatch logging for execute command sessions "
                            "to maintain security audit trails"
                        ),
                    }
                )

            # Check KMS encryption
            kms_key_id = execute_command_config.get("kmsKeyId")
            if not kms_key_id:
                recommendations.append(
                    {
                        "title": "Enable KMS Encryption for Execute Command",
                        "severity": "Medium",
                        "category": "encryption",
                        "resource": f"Cluster: {cluster_name}",
                        "issue": (
                            "Execute command sessions are not encrypted with "
                            "customer-managed KMS keys"
                        ),
                        "recommendation": (
                            "Configure KMS encryption for execute command sessions "
                            "to protect sensitive data"
                        ),
                    }
                )

        # Check cluster status
        status = cluster_info.get("status", "")
        if status != "ACTIVE":
            recommendations.append(
                {
                    "title": "Review Cluster Status",
                    "severity": "High",
                    "category": "availability",
                    "resource": f"Cluster: {cluster_name}",
                    "issue": f"Cluster status is {status}, not ACTIVE",
                    "recommendation": (
                        "Investigate and resolve cluster status issues to ensure proper operation"
                    ),
                }
            )

        return recommendations

    def _analyze_service_security(
        self, service: Dict[str, Any], service_name: str, cluster_name: str, region: str
    ) -> List[Dict[str, Any]]:
        """Analyze service-level security configurations."""
        recommendations = []

        # Check public IP assignment
        network_config = service.get("networkConfiguration", {}).get("awsvpcConfiguration", {})
        if network_config.get("assignPublicIp") == "ENABLED":
            recommendations.append(
                {
                    "title": "Disable Public IP Assignment",
                    "severity": "High",
                    "category": "network_security",
                    "resource": f"Service: {service_name}",
                    "issue": (
                        "Service has public IP assignment enabled, exposing containers "
                        "directly to the internet"
                    ),
                    "recommendation": (
                        "Disable public IP assignment and use NAT Gateway for outbound connectivity"
                    ),
                }
            )

        # Check platform version for Fargate
        launch_type = service.get("launchType", "EC2")
        if launch_type == "FARGATE":
            platform_version = service.get("platformVersion", "LATEST")
            if platform_version == "LATEST":
                recommendations.append(
                    {
                        "title": "Pin Fargate Platform Version for Security Consistency",
                        "severity": "Medium",
                        "category": "security",
                        "resource": f"Service: {service_name}",
                        "issue": (
                            "Using LATEST platform version can introduce unexpected "
                            "security changes"
                        ),
                        "recommendation": (
                            "Pin to a specific Fargate platform version to maintain "
                            "consistent security configuration"
                        ),
                    }
                )

        # Check service connect configuration
        service_connect_config = service.get("serviceConnectConfiguration", {})
        if service_connect_config.get("enabled", False):
            namespace = service_connect_config.get("namespace")
            if not namespace:
                recommendations.append(
                    {
                        "title": "Configure Service Connect Namespace",
                        "severity": "Medium",
                        "category": "network_security",
                        "resource": f"Service: {service_name}",
                        "issue": "Service Connect is enabled but no namespace is configured",
                        "recommendation": (
                            "Configure a proper namespace for Service Connect to ensure "
                            "secure service-to-service communication"
                        ),
                    }
                )

        # Check security groups
        security_groups = network_config.get("securityGroups", [])
        if not security_groups:
            recommendations.append(
                {
                    "title": "Configure Security Groups",
                    "severity": "High",
                    "category": "network_security",
                    "resource": f"Service: {service_name}",
                    "issue": "No security groups configured for the service",
                    "recommendation": (
                        "Configure appropriate security groups to control network access"
                    ),
                }
            )

        # Check service tags for compliance
        service_tags = service.get("tags", [])
        self._analyze_service_tags_security(
            service_tags, service_name, cluster_name, region, recommendations
        )

        # Check deployment configuration
        deployment_config = service.get("deploymentConfiguration", {})

        # Check circuit breaker (availability feature, but impacts security through stability)
        circuit_breaker = deployment_config.get("deploymentCircuitBreaker", {})
        if not circuit_breaker.get("enable", False):
            recommendations.append(
                {
                    "title": "Enable Deployment Circuit Breaker",
                    "severity": "Low",
                    "category": "availability",
                    "resource": f"Service: {service_name}",
                    "issue": "Deployment circuit breaker is not enabled",
                    "recommendation": (
                        "Enable circuit breaker to prevent failed deployments from "
                        "affecting service availability"
                    ),
                }
            )

        return recommendations

    def _analyze_service_tags_security(
        self,
        service_tags: List[Dict[str, Any]],
        service_name: str,
        cluster_name: str,
        region: str,
        recommendations: List[Dict[str, Any]],
    ) -> None:
        """Analyze service tags for security-relevant issues."""
        # Check for tags that might expose sensitive information
        for tag in service_tags:
            tag_key = tag.get("key", "").lower()
            tag_value = tag.get("value", "")

            # Check for potentially sensitive information in tags
            if any(keyword in tag_key for keyword in ["password", "secret", "key", "token"]):
                recommendations.append(
                    {
                        "title": "Remove Sensitive Information from Tags",
                        "severity": "High",
                        "category": "secrets",
                        "resource": f"Service: {service_name}",
                        "issue": f"Tag '{tag_key}' may contain sensitive information",
                        "recommendation": (
                            "Remove sensitive information from tags and use AWS "
                            "Secrets Manager instead"
                        ),
                    }
                )

            # Check for overly detailed environment information
            if tag_key in ["environment", "env"] and tag_value.lower() in ["prod", "production"]:
                # This is normal and expected - no recommendation needed
                pass

    def _analyze_task_definition_security(
        self, task_def: Dict[str, Any], service_name: str, cluster_name: str, region: str
    ) -> List[Dict[str, Any]]:
        """Analyze task definition security configurations."""
        recommendations = []

        # Check for missing task role
        task_role_arn = task_def.get("taskRoleArn")
        if not task_role_arn:
            recommendations.append(
                {
                    "title": "Configure Task IAM Role",
                    "severity": "High",
                    "category": "iam_security",
                    "resource": f"Task Definition: {task_def.get('family', 'unknown')}",
                    "issue": "No task IAM role configured for access control",
                    "recommendation": "Configure task IAM roles with least privilege access",
                }
            )

        # Check for missing execution role
        execution_role_arn = task_def.get("executionRoleArn")
        if not execution_role_arn:
            recommendations.append(
                {
                    "title": "Configure Execution IAM Role",
                    "severity": "High",
                    "category": "iam_security",
                    "resource": f"Task Definition: {task_def.get('family', 'unknown')}",
                    "issue": "No execution IAM role configured",
                    "recommendation": "Configure execution IAM role for ECS agent operations",
                }
            )

        # Analyze container security
        for container in task_def.get("containerDefinitions", []):
            container_name = container.get("name", "unknown")
            container_recommendations = self._analyze_container_security(
                container, container_name, service_name, cluster_name, region
            )
            recommendations.extend(container_recommendations)

        # Check for Fargate resource configuration
        requires_compatibilities = task_def.get("requiresCompatibilities", [])
        if "FARGATE" in requires_compatibilities:
            cpu = task_def.get("cpu")
            memory = task_def.get("memory")

            if not cpu or not memory:
                recommendations.append(
                    {
                        "title": "Configure Fargate Resource Limits",
                        "severity": "Medium",
                        "category": "security",
                        "resource": f"Task Definition: {task_def.get('family', 'unknown')}",
                        "issue": "Missing CPU or memory configuration for Fargate task",
                        "recommendation": (
                            "Configure appropriate CPU and memory limits for proper "
                            "resource isolation"
                        ),
                    }
                )

        # Check network mode
        network_mode = task_def.get("networkMode", "bridge")
        if network_mode == "host":
            recommendations.append(
                {
                    "title": "Avoid Host Network Mode",
                    "severity": "High",
                    "category": "network_security",
                    "resource": f"Task Definition: {task_def.get('family', 'unknown')}",
                    "issue": "Task definition uses host network mode, bypassing network isolation",
                    "recommendation": (
                        "Use awsvpc network mode for better network isolation and security"
                    ),
                }
            )

        # Check PID mode
        pid_mode = task_def.get("pidMode")
        if pid_mode == "host":
            recommendations.append(
                {
                    "title": "Avoid Host PID Mode",
                    "severity": "High",
                    "category": "container_security",
                    "resource": f"Task Definition: {task_def.get('family', 'unknown')}",
                    "issue": (
                        "Task definition uses host PID mode, allowing access to host processes"
                    ),
                    "recommendation": (
                        "Remove pidMode or use task PID mode for better process isolation"
                    ),
                }
            )

        # Check IPC mode
        ipc_mode = task_def.get("ipcMode")
        if ipc_mode == "host":
            recommendations.append(
                {
                    "title": "Avoid Host IPC Mode",
                    "severity": "High",
                    "category": "container_security",
                    "resource": f"Task Definition: {task_def.get('family', 'unknown')}",
                    "issue": (
                        "Task definition uses host IPC mode, allowing access to host IPC resources"
                    ),
                    "recommendation": "Remove ipcMode or use task IPC mode for better isolation",
                }
            )

        return recommendations

    def _analyze_container_security(
        self,
        container: Dict[str, Any],
        container_name: str,
        service_name: str,
        cluster_name: str,
        region: str,
    ) -> List[Dict[str, Any]]:
        """Analyze container security configurations."""
        recommendations = []

        # Check for root user
        user = container.get("user")
        if user == "0" or user == "root" or not user:
            recommendations.append(
                {
                    "title": "Configure Container to Run as Non-Root User",
                    "severity": "High",
                    "category": "container_security",
                    "resource": f"Container: {container_name}",
                    "issue": (
                        "Container is configured to run as root user, violating "
                        "principle of least privilege"
                    ),
                    "recommendation": "Configure container to run as non-privileged user",
                }
            )

        # Check for latest tag
        image = container.get("image", "")
        if image.endswith(":latest") or ":" not in image:
            recommendations.append(
                {
                    "title": "Avoid Latest Tag in Container Images",
                    "severity": "Medium",
                    "category": "container_security",
                    "resource": f"Container: {container_name}",
                    "issue": "Container image uses 'latest' tag, making deployments unpredictable",
                    "recommendation": "Use specific, immutable image tags with semantic versioning",
                }
            )

        # Check for read-only root filesystem
        if not container.get("readonlyRootFilesystem", False):
            recommendations.append(
                {
                    "title": "Enable Read-Only Root Filesystem",
                    "severity": "Medium",
                    "category": "container_security",
                    "resource": f"Container: {container_name}",
                    "issue": "Container has writable root filesystem",
                    "recommendation": (
                        "Enable read-only root filesystem to prevent runtime tampering"
                    ),
                }
            )

        # Check for privileged mode
        if container.get("privileged", False):
            recommendations.append(
                {
                    "title": "Disable Privileged Mode",
                    "severity": "High",
                    "category": "container_security",
                    "resource": f"Container: {container_name}",
                    "issue": "Container is running in privileged mode",
                    "recommendation": (
                        "Disable privileged mode and use specific capabilities if needed"
                    ),
                }
            )

        # Check for health check
        if not container.get("healthCheck"):
            recommendations.append(
                {
                    "title": "Configure Container Health Check",
                    "severity": "Medium",
                    "category": "monitoring",
                    "resource": f"Container: {container_name}",
                    "issue": "Container lacks health check configuration",
                    "recommendation": "Implement health checks to verify application functionality",
                }
            )

        # Check for resource limits
        memory = container.get("memory")
        memory_reservation = container.get("memoryReservation")

        if not memory and not memory_reservation:
            recommendations.append(
                {
                    "title": "Configure Memory Limits",
                    "severity": "Medium",
                    "category": "container_security",
                    "resource": f"Container: {container_name}",
                    "issue": "No memory limits configured",
                    "recommendation": (
                        "Configure memory limits to prevent resource exhaustion attacks"
                    ),
                }
            )

        # Check for secrets in environment variables
        environment = container.get("environment", [])
        for env_var in environment:
            env_name = env_var.get("name", "").lower()
            env_value = env_var.get("value", "")

            if any(
                keyword in env_name for keyword in ["password", "secret", "key", "token", "api_key"]
            ):
                if env_value and not env_value.startswith("arn:aws:"):
                    recommendations.append(
                        {
                            "title": "Use AWS Secrets Manager for Sensitive Data",
                            "severity": "High",
                            "category": "secrets",
                            "resource": f"Container: {container_name}",
                            "issue": (
                                f"Environment variable {env_name} contains hardcoded sensitive data"
                            ),
                            "recommendation": (
                                "Migrate to AWS Secrets Manager to prevent credential exposure"
                            ),
                        }
                    )

        # Check for dangerous capabilities
        linux_parameters = container.get("linuxParameters", {})
        capabilities = linux_parameters.get("capabilities", {})
        add_capabilities = capabilities.get("add", [])

        dangerous_caps = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE"]
        for cap in add_capabilities:
            if cap in dangerous_caps:
                recommendations.append(
                    {
                        "title": "Review Dangerous Container Capabilities",
                        "severity": "High",
                        "category": "container_security",
                        "resource": f"Container: {container_name}",
                        "issue": (
                            f"Container has dangerous capability {cap} which "
                            f"increases attack surface"
                        ),
                        "recommendation": (
                            "Remove unnecessary capabilities and follow principle "
                            "of least privilege"
                        ),
                    }
                )

        # Check for port mappings
        port_mappings = container.get("portMappings", [])
        for port_mapping in port_mappings:
            host_port = port_mapping.get("hostPort", 0)
            container_port = port_mapping.get("containerPort", 0)

            # Check for dynamic port allocation (security best practice)
            if host_port == 0:
                # This is good - dynamic port allocation
                pass
            elif host_port == container_port:
                recommendations.append(
                    {
                        "title": "Use Dynamic Port Allocation",
                        "severity": "Low",
                        "category": "network_security",
                        "resource": f"Container: {container_name}",
                        "issue": (
                            f"Static port mapping {host_port}:{container_port} reduces "
                            f"security through predictability"
                        ),
                        "recommendation": (
                            "Use dynamic port allocation (hostPort: 0) for better security"
                        ),
                    }
                )

        # Check for logging configuration
        log_configuration = container.get("logConfiguration", {})
        if not log_configuration:
            recommendations.append(
                {
                    "title": "Configure Container Logging",
                    "severity": "Medium",
                    "category": "monitoring",
                    "resource": f"Container: {container_name}",
                    "issue": "No logging configuration specified for container",
                    "recommendation": (
                        "Configure CloudWatch Logs or other logging driver for security monitoring"
                    ),
                }
            )

        return recommendations

    def _analyze_network_infrastructure(
        self, network_data: Dict[str, Any], cluster_name: str, region: str
    ) -> List[Dict[str, Any]]:
        """Analyze network infrastructure security."""
        recommendations = []

        # Analyze Security Groups
        security_groups_data = network_data.get("security_groups", {})

        # Handle raw AWS API response format
        if "SecurityGroups" in security_groups_data:
            security_groups_list = security_groups_data["SecurityGroups"]
        else:
            security_groups_list = (
                list(security_groups_data.values())
                if isinstance(security_groups_data, dict)
                else []
            )

        for sg_info in security_groups_list:
            if not isinstance(sg_info, dict):
                continue

            sg_id = sg_info.get("GroupId", "unknown")
            ingress_rules = sg_info.get("IpPermissions", [])

            for rule in ingress_rules:
                # Check for overly permissive rules
                ip_ranges = rule.get("IpRanges", [])
                for ip_range in ip_ranges:
                    cidr = ip_range.get("CidrIp", "")
                    if cidr == "0.0.0.0/0":
                        from_port = rule.get("FromPort", 0)
                        to_port = rule.get("ToPort", 0)

                        if from_port == 22 or to_port == 22:
                            recommendations.append(
                                {
                                    "title": "Restrict SSH Access from Internet",
                                    "severity": "High",
                                    "category": "network_security",
                                    "resource": f"Security Group: {sg_id}",
                                    "issue": "SSH port (22) is open to the internet (0.0.0.0/0)",
                                    "recommendation": (
                                        "Restrict SSH access to specific IP ranges or use AWS "
                                        "Systems Manager Session Manager"
                                    ),
                                }
                            )
                        elif from_port == 3389 or to_port == 3389:
                            recommendations.append(
                                {
                                    "title": "Restrict RDP Access from Internet",
                                    "severity": "High",
                                    "category": "network_security",
                                    "resource": f"Security Group: {sg_id}",
                                    "issue": "RDP port (3389) is open to the internet (0.0.0.0/0)",
                                    "recommendation": (
                                        "Restrict RDP access to specific IP ranges or use AWS "
                                        "Systems Manager Session Manager"
                                    ),
                                }
                            )
                        elif from_port not in [80, 443]:
                            recommendations.append(
                                {
                                    "title": "Review Overly Permissive Security Group Rules",
                                    "severity": "High",
                                    "category": "network_security",
                                    "resource": f"Security Group: {sg_id}",
                                    "issue": (
                                        f"Port {from_port} is open to the internet (0.0.0.0/0)"
                                    ),
                                    "recommendation": (
                                        "Restrict access to specific IP ranges or remove "
                                        "unnecessary rules"
                                    ),
                                }
                            )

        # Analyze VPC configuration
        vpcs_data = network_data.get("vpcs", {})

        # Handle raw AWS API response format
        if "Vpcs" in vpcs_data:
            vpcs_list = vpcs_data["Vpcs"]
        else:
            vpcs_list = list(vpcs_data.values()) if isinstance(vpcs_data, dict) else []

        for vpc_info in vpcs_list:
            if not isinstance(vpc_info, dict):
                continue

            vpc_id = vpc_info.get("VpcId", "unknown")

            # Check for default VPC usage
            if vpc_info.get("IsDefault", False):
                recommendations.append(
                    {
                        "title": "Avoid Using Default VPC for Production Workloads",
                        "severity": "Medium",
                        "category": "network",
                        "resource": f"VPC: {vpc_id}",
                        "issue": (
                            "Using default VPC which may have less secure default configurations"
                        ),
                        "recommendation": "Create a custom VPC with proper security configurations",
                    }
                )

            # Recommend VPC Flow Logs
            recommendations.append(
                {
                    "title": "Enable VPC Flow Logs",
                    "severity": "Medium",
                    "category": "network_security",
                    "resource": f"VPC: {vpc_id}",
                    "issue": "VPC Flow Logs should be enabled for network traffic visibility",
                    "recommendation": (
                        "Enable VPC Flow Logs to monitor network traffic and "
                        "detect security anomalies"
                    ),
                }
            )

        # Analyze Subnets
        subnets_data = network_data.get("subnets", {})

        # Handle raw AWS API response format
        if "Subnets" in subnets_data:
            subnets_list = subnets_data["Subnets"]
        else:
            subnets_list = list(subnets_data.values()) if isinstance(subnets_data, dict) else []

        for subnet_info in subnets_list:
            if not isinstance(subnet_info, dict):
                continue

            subnet_id = subnet_info.get("SubnetId", "unknown")
            if subnet_info.get("MapPublicIpOnLaunch", False):
                recommendations.append(
                    {
                        "title": "Disable Auto-Assign Public IP for Subnets",
                        "severity": "Medium",
                        "category": "network_security",
                        "resource": f"Subnet: {subnet_id}",
                        "issue": "Subnet automatically assigns public IP addresses",
                        "recommendation": (
                            "Disable auto-assign public IP and use NAT Gateway "
                            "for outbound connectivity"
                        ),
                    }
                )

        # Analyze Load Balancers
        load_balancers_data = network_data.get("load_balancers", {})

        # Handle raw AWS API response format
        if "LoadBalancers" in load_balancers_data:
            load_balancers_list = load_balancers_data["LoadBalancers"]
        else:
            load_balancers_list = (
                list(load_balancers_data.values()) if isinstance(load_balancers_data, dict) else []
            )

        for lb_info in load_balancers_list:
            if not isinstance(lb_info, dict):
                continue

            lb_name = lb_info.get("LoadBalancerName", "unknown")

            # Check if load balancer is internet-facing
            scheme = lb_info.get("Scheme", "internal")
            if scheme == "internet-facing":
                recommendations.append(
                    {
                        "title": "Review Internet-Facing Load Balancer Security",
                        "severity": "Medium",
                        "category": "network_security",
                        "resource": f"Load Balancer: {lb_name}",
                        "issue": (
                            "Load balancer is internet-facing, ensure proper "
                            "security controls are in place"
                        ),
                        "recommendation": (
                            "Verify security groups, SSL/TLS configuration, and "
                            "access controls for internet-facing load balancer"
                        ),
                    }
                )

            # Check security groups
            security_groups = lb_info.get("SecurityGroups", [])
            if not security_groups:
                recommendations.append(
                    {
                        "title": "Configure Security Groups for Load Balancer",
                        "severity": "High",
                        "category": "network_security",
                        "resource": f"Load Balancer: {lb_name}",
                        "issue": "No security groups configured for load balancer",
                        "recommendation": (
                            "Configure appropriate security groups to control "
                            "access to the load balancer"
                        ),
                    }
                )

        # Analyze Route Tables
        route_tables_data = network_data.get("route_tables", {})

        # Handle raw AWS API response format
        if "RouteTables" in route_tables_data:
            route_tables_list = route_tables_data["RouteTables"]
        else:
            route_tables_list = (
                list(route_tables_data.values()) if isinstance(route_tables_data, dict) else []
            )

        for rt_info in route_tables_list:
            if not isinstance(rt_info, dict):
                continue

            rt_id = rt_info.get("RouteTableId", "unknown")
            routes = rt_info.get("Routes", [])

            # Check for overly broad routes
            for route in routes:
                destination = route.get("DestinationCidrBlock", "")
                gateway_id = route.get("GatewayId", "")

                # Check for routes to 0.0.0.0/0 through internet gateway
                if destination == "0.0.0.0/0" and gateway_id and gateway_id.startswith("igw-"):
                    recommendations.append(
                        {
                            "title": "Review Internet Gateway Routes",
                            "severity": "Low",
                            "category": "network_security",
                            "resource": f"Route Table: {rt_id}",
                            "issue": (
                                "Route table has default route (0.0.0.0/0) to Internet Gateway"
                            ),
                            "recommendation": (
                                "Ensure this route table is only associated with "
                                "public subnets that require internet access"
                            ),
                        }
                    )

        return recommendations

    def _generate_analysis_summary(self, recommendations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a summary of the security analysis."""
        severity_counts = {}
        category_counts = {}

        for rec in recommendations:
            severity = rec.get("severity", "Unknown")
            category = rec.get("category", "Unknown")

            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1

        return {
            "total_recommendations": len(recommendations),
            "severity_breakdown": severity_counts,
            "category_breakdown": category_counts,
        }


async def analyze_ecs_security(
    cluster_names: Optional[List[str]] = None,
    regions: Optional[List[str]] = None,
    analysis_scope: Optional[str] = "basic",
) -> Dict[str, Any]:
    """
    Comprehensive security analysis of ECS deployments.

    Args:
        cluster_names: List of cluster names to analyze. If None, discovers all clusters.
        regions: List of regions to analyze. Defaults to ['us-east-1'].
        analysis_scope: Scope of analysis ('basic' for initial implementation).

    Returns:
        Dictionary containing security analysis results.
    """
    try:
        logger.info(
            f"Starting ECS security analysis for clusters: {cluster_names}, regions: {regions}"
        )

        # Default regions
        if not regions:
            regions = ["us-east-1"]

        # Initialize data adapter and analyzer
        data_adapter = DataAdapter()
        security_analyzer = SecurityAnalyzer()

        # Collect data for all specified regions and clusters
        all_data = {}

        for region in regions:
            try:
                logger.info(f"Analyzing region: {region}")

                if cluster_names:
                    clusters = cluster_names
                else:
                    # Use existing utility to find clusters
                    clusters = await find_clusters()

                region_data = {"clusters": {}}

                for cluster_name in clusters:
                    try:
                        cluster_security_data = await data_adapter.adapt_to_security_format(
                            cluster_name, region
                        )

                        if region in cluster_security_data:
                            region_data["clusters"].update(
                                cluster_security_data[region]["clusters"]
                            )
                    except Exception as e:
                        logger.error(f"Error collecting data for cluster {cluster_name}: {e}")
                        region_data["clusters"][cluster_name] = {
                            "error": str(e),
                            "cluster_name": cluster_name,
                            "region": region,
                        }

                all_data[region] = region_data

            except Exception as e:
                logger.error(f"Error analyzing region {region}: {e}")
                all_data[region] = {"error": str(e), "region": region}

        # Perform security analysis
        analysis_result = security_analyzer.analyze(all_data)

        # Add metadata
        analysis_result.update(
            {
                "regions_analyzed": regions,
                "clusters_analyzed": cluster_names or "all_discovered",
                "analysis_scope": analysis_scope,
                "status": "success",
            }
        )

        logger.info(f"Security analysis completed. Found {analysis_result['total_issues']} issues.")
        return analysis_result

    except Exception as e:
        logger.error(f"Error in analyze_ecs_security: {e}")
        return {"status": "error", "error": str(e), "timestamp": datetime.utcnow().isoformat()}
