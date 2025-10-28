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
API for ECS security analysis operations.

This module provides functions for analyzing ECS cluster security configurations
and generating security recommendations.
"""

import logging
import os
from typing import Any, Dict

from awslabs.ecs_mcp_server.api.resource_management import ecs_api_operation

logger = logging.getLogger(__name__)


def get_target_region() -> str:
    """
    Get the target AWS region for security analysis from environment variable.

    Returns:
        AWS region name from AWS_REGION environment variable (defaults to 'us-east-1')
    """
    region = os.environ.get("AWS_REGION", "us-east-1")
    logger.info(f"Using region from environment: {region}")
    return region


async def get_clusters_with_metadata(region: str) -> list[Dict[str, Any]]:
    """
    Get all ECS clusters in the specified region with their metadata.

    Args:
        region: AWS region to get clusters from

    Returns:
        List of cluster dictionaries with metadata

    Raises:
        Exception: If retrieving clusters fails
    """
    logger.info(f"Listing ECS clusters in region: {region}")

    try:
        # List cluster ARNs
        list_response = await ecs_api_operation(api_operation="ListClusters", api_params={})

        cluster_arns = list_response.get("clusterArns", [])

        if not cluster_arns:
            logger.info(f"No clusters found in region {region}")
            return []

        logger.info(f"Found {len(cluster_arns)} cluster(s) in region {region}")

        # Describe clusters to get metadata
        describe_response = await ecs_api_operation(
            api_operation="DescribeClusters",
            api_params={
                "clusters": cluster_arns,
                "include": ["ATTACHMENTS", "SETTINGS", "STATISTICS", "TAGS"],
            },
        )

        clusters = describe_response.get("clusters", [])

        # Format cluster information
        all_clusters = []
        for cluster in clusters:
            cluster_info = {
                "cluster_name": cluster.get("clusterName"),
                "cluster_arn": cluster.get("clusterArn"),
                "status": cluster.get("status"),
                "running_tasks_count": cluster.get("runningTasksCount", 0),
                "pending_tasks_count": cluster.get("pendingTasksCount", 0),
                "active_services_count": cluster.get("activeServicesCount", 0),
                "registered_container_instances_count": cluster.get(
                    "registeredContainerInstancesCount", 0
                ),
                "tags": {tag["key"]: tag["value"] for tag in cluster.get("tags", [])},
            }
            all_clusters.append(cluster_info)

        logger.info(f"Successfully retrieved metadata for {len(all_clusters)} cluster(s)")
        return all_clusters

    except Exception as e:
        logger.error(f"Error retrieving clusters in region {region}: {e}")
        raise Exception(f"Failed to retrieve clusters in region '{region}': {str(e)}") from e


def format_clusters_for_display(clusters: list[Dict[str, Any]], region: str) -> str:
    """
    Format cluster data into a user-friendly display string.

    Args:
        clusters: List of cluster dictionaries
        region: AWS region name

    Returns:
        Formatted string with cluster information for display
    """
    if not clusters:
        return f"""
No ECS clusters found in region: {region}

To create a cluster, you can use the AWS CLI:
```bash
aws ecs create-cluster --cluster-name my-cluster --region {region}
```

Or use the AWS Console to create a cluster in the ECS service.
"""

    # Build the formatted output
    lines = [
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"📋 ECS CLUSTERS IN REGION: {region}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "",
        f"Found {len(clusters)} cluster(s):",
        "",
    ]

    for i, cluster in enumerate(clusters, 1):
        cluster_name = cluster.get("cluster_name", "Unknown")
        status = cluster.get("status", "Unknown")
        running_tasks = cluster.get("running_tasks_count", 0)
        active_services = cluster.get("active_services_count", 0)

        lines.extend(
            [
                f"{i}. {cluster_name}",
                f"   Status: {status}",
                f"   Running Tasks: {running_tasks}",
                f"   Active Services: {active_services}",
                "",
            ]
        )

    lines.extend(
        [
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "",
            "To analyze a specific cluster, call this tool again with:",
            "  cluster_names=['cluster-name']",
            "",
            "Example:",
            f"  analyze_ecs_security("
            f"cluster_names=['{clusters[0].get('cluster_name')}'], "
            f"region='{region}')",
            "",
        ]
    )

    return "\n".join(lines)
