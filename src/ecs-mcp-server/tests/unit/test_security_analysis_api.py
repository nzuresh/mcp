"""
Unit tests for security analysis API functions.
"""

from unittest.mock import patch

import pytest

from awslabs.ecs_mcp_server.api.security_analysis import (
    RegionValidationError,
    format_cluster_list,
    get_target_region,
    list_clusters_in_region,
    validate_region,
)


def test_validate_region_valid():
    """Test validate_region with a valid region."""
    # Should not raise an exception
    validate_region("us-east-1")
    validate_region("us-west-2")
    validate_region("eu-west-1")


def test_validate_region_invalid():
    """Test validate_region with an invalid region."""
    with pytest.raises(RegionValidationError) as exc_info:
        validate_region("invalid-region")

    assert "Invalid AWS region" in str(exc_info.value)
    assert "invalid-region" in str(exc_info.value)


@patch("awslabs.ecs_mcp_server.api.security_analysis.validate_region")
def test_get_target_region_with_parameter(mock_validate):
    """Test get_target_region when region parameter is provided."""
    result = get_target_region("us-west-2")

    assert result == "us-west-2"
    mock_validate.assert_called_once_with("us-west-2")


@patch("awslabs.ecs_mcp_server.api.security_analysis.validate_region")
@patch.dict("os.environ", {"AWS_REGION": "eu-central-1"})
def test_get_target_region_from_env(mock_validate):
    """Test get_target_region when using environment variable."""
    result = get_target_region(None)

    assert result == "eu-central-1"
    mock_validate.assert_called_once_with("eu-central-1")


@patch("awslabs.ecs_mcp_server.api.security_analysis.validate_region")
@patch.dict("os.environ", {}, clear=True)
def test_get_target_region_default(mock_validate):
    """Test get_target_region when no region specified and no env var."""
    result = get_target_region(None)

    assert result == "us-east-1"
    mock_validate.assert_called_once_with("us-east-1")


@pytest.mark.anyio
@patch("awslabs.ecs_mcp_server.api.security_analysis.ecs_api_operation")
async def test_list_clusters_in_region_success(mock_ecs_api):
    """Test list_clusters_in_region with successful response."""
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

    result = await list_clusters_in_region("us-east-1")

    assert len(result) == 2
    assert result[0]["cluster_name"] == "test-cluster-1"
    assert result[0]["status"] == "ACTIVE"
    assert result[0]["running_tasks_count"] == 5
    assert result[0]["tags"] == {"Environment": "Production"}
    assert result[1]["cluster_name"] == "test-cluster-2"


@pytest.mark.anyio
@patch("awslabs.ecs_mcp_server.api.security_analysis.ecs_api_operation")
async def test_list_clusters_in_region_empty(mock_ecs_api):
    """Test list_clusters_in_region when no clusters exist."""
    mock_ecs_api.return_value = {"clusterArns": []}

    result = await list_clusters_in_region("us-east-1")

    assert result == []
    mock_ecs_api.assert_called_once()


@pytest.mark.anyio
@patch("awslabs.ecs_mcp_server.api.security_analysis.ecs_api_operation")
async def test_list_clusters_in_region_error(mock_ecs_api):
    """Test list_clusters_in_region when API call fails."""
    mock_ecs_api.side_effect = Exception("API Error")

    with pytest.raises(Exception) as exc_info:
        await list_clusters_in_region("us-east-1")

    assert "Failed to list clusters" in str(exc_info.value)


def test_format_cluster_list_with_clusters():
    """Test format_cluster_list with multiple clusters."""
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

    result = format_cluster_list(clusters, "us-east-1")

    assert "ECS CLUSTERS IN REGION: us-east-1" in result
    assert "Found 2 cluster(s)" in result
    assert "prod-cluster" in result
    assert "staging-cluster" in result
    assert "Running Tasks: 10" in result
    assert "Active Services: 5" in result


def test_format_cluster_list_empty():
    """Test format_cluster_list with no clusters."""
    result = format_cluster_list([], "us-west-2")

    assert "No ECS clusters found in region: us-west-2" in result
    assert "create-cluster" in result
