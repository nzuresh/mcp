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
Security Analysis module for ECS MCP Server.
This module provides tools and prompts for analyzing ECS security configurations.
"""

import json
import logging
from datetime import datetime

from fastmcp import FastMCP
from pydantic import Field

from awslabs.ecs_mcp_server.api.security_analysis import (
    collect_cluster_configuration,
    format_cluster_list,
    get_target_region,
    list_clusters_in_region,
    validate_clusters,
)

logger = logging.getLogger(__name__)


def register_module(mcp: FastMCP) -> None:
    """Register security analysis module tools and prompts with the MCP server."""

    # Define pydantic Field descriptions for all parameters
    region_field = Field(
        default=None,
        description=(
            "Optional AWS region to analyze. "
            "If not provided, uses the AWS_REGION environment variable (defaults to 'us-east-1'). "
            "Must be a valid AWS region where ECS is available. "
            "Example: 'us-west-2', 'eu-west-1'"
        ),
    )

    cluster_names_field = Field(
        default=None,
        description=(
            "Optional list of specific cluster names to analyze. "
            "If not provided, lists all available clusters for user selection. "
            "When provided, collects complete configuration data for the specified clusters. "
            "Example: ['prod-cluster', 'staging-cluster']"
        ),
    )

    @mcp.tool(name="analyze_ecs_security", annotations=None)
    async def mcp_analyze_ecs_security(
        region: str | None = region_field,
        cluster_names: list[str] | None = cluster_names_field,
    ) -> str:
        """
        Analyze ECS cluster security configurations or list available clusters.

        This tool provides two modes of operation:
        1. Cluster Discovery: List all available clusters
           (when cluster_names not provided)
        2. Configuration Collection: Collect detailed configuration data
           (when cluster_names provided)

        Interactive Workflow:

        Step 1: List Available Clusters
           - Call with NO cluster_names to list clusters in region
           - Returns formatted list of available clusters with metadata
           - User can review and select which clusters to analyze

        Step 2: Collect Configuration Data
           - Call with specific cluster_names to collect configuration
           - Returns comprehensive JSON configuration data
           - Includes services, task definitions, security groups, IAM roles

        Usage Examples:

        Example 1 - List clusters in default region:
            analyze_ecs_security()
            # Returns list of clusters in AWS_REGION for selection

        Example 2 - List clusters in specific region:
            analyze_ecs_security(region="us-west-2")
            # Returns list of clusters in us-west-2 for selection

        Example 3 - Collect configuration for specific clusters:
            analyze_ecs_security(cluster_names=["prod-cluster"])
            # Returns detailed configuration JSON for prod-cluster

        Example 4 - Analyze multiple clusters in specific region:
            analyze_ecs_security(region="eu-west-1", cluster_names=["web-cluster", "api-cluster"])
            # Returns configuration data for both clusters in eu-west-1

        Configuration Data Collected:
        - Cluster metadata (settings, statistics, tags)
        - Service configurations (network, load balancers, capacity)
        - Task definition details (containers, IAM roles, volumes)
        - Security group rules (ingress/egress permissions)
        - IAM role references and policies
        - Container security settings
        - Network configurations

        Parameters:
            region: Optional AWS region. If None, uses AWS_REGION environment variable.
            cluster_names: Optional list of cluster names. If None, lists available clusters.

        Returns:
            - If cluster_names not provided: Formatted list of available clusters
            - If cluster_names provided: JSON configuration data for analysis

        Error Handling:
            - Invalid region: Returns error with list of valid regions
            - Cluster not found: Returns error with available cluster names
            - Partial failures: Returns data with error details in collection_errors
        """
        try:
            # Step 1: Determine target region
            logger.info("Step 1: Determining target region")
            target_region = get_target_region(region)

            # Step 2: Check operation mode
            if cluster_names is None:
                # Mode 1: List clusters for user selection
                logger.info(
                    f"Step 2: Listing clusters in region '{target_region}' for user selection"
                )
                clusters = await list_clusters_in_region(target_region)
                return format_cluster_list(clusters, target_region)
            else:
                # Mode 2: Collect configuration data for specified clusters
                logger.info(
                    f"Step 2: Collecting configuration for {len(cluster_names)} "
                    f"cluster(s) in region '{target_region}'"
                )

                # Step 2a: Validate clusters exist
                logger.info("Step 2a: Validating cluster existence")
                validated_arns = await validate_clusters(cluster_names, target_region)
                logger.info(f"Successfully validated {len(validated_arns)} cluster(s)")

                # Step 2b: Collect configuration for each cluster
                logger.info("Step 2b: Collecting cluster configurations")
                cluster_configs = []
                for cluster_name in cluster_names:
                    try:
                        config = await collect_cluster_configuration(target_region, cluster_name)
                        cluster_configs.append(config)
                    except Exception as e:
                        logger.error(
                            f"Failed to collect configuration for cluster '{cluster_name}': {e}"
                        )
                        # Add error info to the config
                        error_config = {
                            "cluster_name": cluster_name,
                            "region": target_region,
                            "collection_error": str(e),
                            "cluster_metadata": {},
                            "services": [],
                            "task_definitions": [],
                            "security_groups": [],
                            "collection_errors": [f"Failed to collect configuration: {str(e)}"],
                        }
                        cluster_configs.append(error_config)

                # Step 2c: Format response
                response_data = {
                    "analysis_type": "ecs_security_configuration",
                    "region": target_region,
                    "clusters_analyzed": len(cluster_configs),
                    "cluster_configurations": cluster_configs,
                    "collection_timestamp": datetime.utcnow().isoformat() + "Z",
                }

                logger.info(
                    f"Configuration collection complete: "
                    f"{len(cluster_configs)} cluster(s) processed"
                )
                return json.dumps(response_data, indent=2, default=str)

        except Exception as e:
            import traceback

            error_msg = f"Error during security analysis: {str(e)}"
            logger.error(error_msg)
            logger.error(f"Traceback: {traceback.format_exc()}")
            return f"❌ {error_msg}\n\nDetailed error:\n{traceback.format_exc()}"

    # Register prompt patterns for security analysis

    @mcp.prompt("analyze ecs security")
    def analyze_ecs_security_prompt():
        """User wants to analyze ECS security"""
        return ["analyze_ecs_security"]

    @mcp.prompt("check ecs security")
    def check_ecs_security_prompt():
        """User wants to check ECS security"""
        return ["analyze_ecs_security"]

    @mcp.prompt("ecs security audit")
    def ecs_security_audit_prompt():
        """User wants to perform an ECS security audit"""
        return ["analyze_ecs_security"]

    @mcp.prompt("security best practices")
    def security_best_practices_prompt():
        """User wants to check security best practices"""
        return ["analyze_ecs_security"]

    @mcp.prompt("security recommendations")
    def security_recommendations_prompt():
        """User wants security recommendations"""
        return ["analyze_ecs_security"]

    @mcp.prompt("scan ecs clusters")
    def scan_ecs_clusters_prompt():
        """User wants to scan ECS clusters for security issues"""
        return ["analyze_ecs_security"]

    @mcp.prompt("ecs security scan")
    def ecs_security_scan_prompt():
        """User wants to perform an ECS security scan"""
        return ["analyze_ecs_security"]

    @mcp.prompt("list ecs clusters")
    def list_ecs_clusters_prompt():
        """User wants to list ECS clusters"""
        return ["analyze_ecs_security"]
