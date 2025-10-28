"""
Unit tests for security analysis API functions.
"""

from unittest.mock import patch

import pytest

from awslabs.ecs_mcp_server.api.security_analysis import (
    format_clusters_for_display,
    get_clusters_with_metadata,
    get_target_region,
)


@patch.dict("os.environ", {"AWS_REGION": "eu-central-1"})
def test_get_target_region_from_env():
    """Test get_target_region when using environment variable."""
    result = get_target_region()

    assert result == "eu-central-1"


@patch.dict("os.environ", {}, clear=True)
def test_get_target_region_default():
    """Test get_target_region when no region specified and no env var."""
    result = get_target_region()

    assert result == "us-east-1"


@pytest.mark.anyio
@patch("awslabs.ecs_mcp_server.api.security_analysis.ecs_api_operation")
async def test_get_clusters_with_metadata_success(mock_ecs_api):
    """Test get_clusters_with_metadata with successful response."""
    # Mock ListClusters response
    mock_ecs_api.side_effect = [
        {
            "clusterArns": [
                "arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster-1",
                "arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster-2",
            ]
        },
        {
            "clusters": [
                {
                    "clusterName": "test-cluster-1",
                    "clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster-1",
                    "status": "ACTIVE",
                    "runningTasksCount": 5,
                    "pendingTasksCount": 0,
                    "activeServicesCount": 3,
                    "registeredContainerInstancesCount": 2,
                    "tags": [{"key": "Environment", "value": "Production"}],
                },
                {
                    "clusterName": "test-cluster-2",
                    "clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster-2",
                    "status": "ACTIVE",
                    "runningTasksCount": 2,
                    "pendingTasksCount": 1,
                    "activeServicesCount": 1,
                    "registeredContainerInstancesCount": 1,
                    "tags": [],
                },
            ]
        },
    ]

    result = await get_clusters_with_metadata("us-east-1")

    assert len(result) == 2
    assert result[0]["cluster_name"] == "test-cluster-1"
    assert result[0]["status"] == "ACTIVE"
    assert result[0]["running_tasks_count"] == 5
    assert result[0]["tags"] == {"Environment": "Production"}
    assert result[1]["cluster_name"] == "test-cluster-2"


@pytest.mark.anyio
@patch("awslabs.ecs_mcp_server.api.security_analysis.ecs_api_operation")
async def test_get_clusters_with_metadata_empty(mock_ecs_api):
    """Test get_clusters_with_metadata when no clusters exist."""
    mock_ecs_api.return_value = {"clusterArns": []}

    result = await get_clusters_with_metadata("us-east-1")

    assert result == []
    mock_ecs_api.assert_called_once()


@pytest.mark.anyio
@patch("awslabs.ecs_mcp_server.api.security_analysis.ecs_api_operation")
async def test_get_clusters_with_metadata_error(mock_ecs_api):
    """Test get_clusters_with_metadata when API call fails."""
    mock_ecs_api.side_effect = Exception("API Error")

    with pytest.raises(Exception) as exc_info:
        await get_clusters_with_metadata("us-east-1")

    assert "Failed to retrieve clusters" in str(exc_info.value)


def test_format_clusters_for_display_with_clusters():
    """Test format_clusters_for_display with multiple clusters."""
    clusters = [
        {
            "cluster_name": "prod-cluster",
            "status": "ACTIVE",
            "running_tasks_count": 10,
            "active_services_count": 5,
        },
        {
            "cluster_name": "staging-cluster",
            "status": "ACTIVE",
            "running_tasks_count": 3,
            "active_services_count": 2,
        },
    ]

    result = format_clusters_for_display(clusters, "us-east-1")

    assert "ECS CLUSTERS IN REGION: us-east-1" in result
    assert "Found 2 cluster(s)" in result
    assert "prod-cluster" in result
    assert "staging-cluster" in result
    assert "Running Tasks: 10" in result
    assert "Active Services: 5" in result


def test_format_clusters_for_display_empty():
    """Test format_clusters_for_display with no clusters."""
    result = format_clusters_for_display([], "us-west-2")

    assert "No ECS clusters found in region: us-west-2" in result
    assert "create-cluster" in result
