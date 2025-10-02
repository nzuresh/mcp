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
        """Basic security analysis of ECS configurations."""
        recommendations = []

        for region, region_data in ecs_data.items():
            if "error" in region_data:
                continue

            for cluster_name, cluster_data in region_data.get("clusters", {}).items():
                if "error" in cluster_data:
                    continue

                # Basic cluster-level security analysis
                recommendations.extend(
                    self._analyze_cluster_security(cluster_name, cluster_data, region)
                )

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
