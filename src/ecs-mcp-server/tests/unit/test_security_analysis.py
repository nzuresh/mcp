"""
Unit tests for the ECS security analysis API module.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from awslabs.ecs_mcp_server.api.security_analysis import (
    DataAdapter,
    SecurityAnalyzer,
    analyze_ecs_security,
)


class TestDataAdapter:
    """Tests for the DataAdapter class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.data_adapter = DataAdapter()

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.ecs_api_operation")
    async def test_collect_cluster_data_success(self, mock_ecs_api):
        """Test successful cluster data collection."""
        # Mock successful cluster response
        mock_cluster_response = {
            "clusters": [
                {
                    "clusterName": "test-cluster",
                    "clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster",
                    "status": "ACTIVE",
                    "settings": [{"name": "containerInsights", "value": "enabled"}],
                    "configuration": {"executeCommandConfiguration": {"logging": "OVERRIDE"}},
                }
            ]
        }

        mock_capacity_providers_response = {
            "capacityProviders": [{"name": "FARGATE", "status": "ACTIVE"}]
        }

        # Configure mock to return different responses based on operation
        def mock_ecs_operation(operation, params):
            if operation == "DescribeClusters":
                return mock_cluster_response
            elif operation == "DescribeCapacityProviders":
                return mock_capacity_providers_response
            else:
                return {"error": "Unknown operation"}

        mock_ecs_api.side_effect = mock_ecs_operation

        # Call the method
        result = await self.data_adapter.collect_cluster_data("test-cluster", "us-east-1")

        # Verify the result
        assert result["status"] == "success"
        assert result["cluster_name"] == "test-cluster"
        assert result["region"] == "us-east-1"
        assert result["cluster"]["clusterName"] == "test-cluster"
        assert len(result["capacity_providers"]) == 1
        assert result["capacity_providers"][0]["name"] == "FARGATE"

        # Verify API calls were made
        assert mock_ecs_api.call_count == 2

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.ecs_api_operation")
    async def test_collect_cluster_data_cluster_not_found(self, mock_ecs_api):
        """Test cluster data collection when cluster is not found."""
        # Mock empty cluster response
        mock_ecs_api.return_value = {"clusters": []}

        # Call the method
        result = await self.data_adapter.collect_cluster_data("nonexistent-cluster", "us-east-1")

        # Verify the result
        assert "error" in result
        assert "Cluster 'nonexistent-cluster' not found" in result["error"]
        assert result["cluster_name"] == "nonexistent-cluster"
        assert result["region"] == "us-east-1"

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.ecs_api_operation")
    async def test_collect_cluster_data_api_error(self, mock_ecs_api):
        """Test cluster data collection when API returns error."""
        # Mock API error response
        mock_ecs_api.return_value = {"error": "Access denied", "status": "failed"}

        # Call the method
        result = await self.data_adapter.collect_cluster_data("test-cluster", "us-east-1")

        # Verify the result
        assert "error" in result
        assert "Access denied" in result["error"]
        assert result["cluster_name"] == "test-cluster"
        assert result["region"] == "us-east-1"

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.ecs_api_operation")
    async def test_collect_cluster_data_exception(self, mock_ecs_api):
        """Test cluster data collection when exception occurs."""
        # Mock exception
        mock_ecs_api.side_effect = Exception("Network error")

        # Call the method
        result = await self.data_adapter.collect_cluster_data("test-cluster", "us-east-1")

        # Verify the result
        assert "error" in result
        assert "Network error" in result["error"]
        assert result["cluster_name"] == "test-cluster"
        assert result["region"] == "us-east-1"

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.find_task_definitions")
    @patch("awslabs.ecs_mcp_server.api.security_analysis.ecs_api_operation")
    async def test_collect_service_data_success(self, mock_ecs_api, mock_find_task_defs):
        """Test successful service data collection."""
        # Mock service list response
        mock_list_services_response = {
            "serviceArns": ["arn:aws:ecs:us-east-1:123456789012:service/test-cluster/test-service"]
        }

        # Mock service describe response
        mock_describe_services_response = {
            "services": [
                {
                    "serviceName": "test-service",
                    "serviceArn": (
                        "arn:aws:ecs:us-east-1:123456789012:service/test-cluster/test-service"
                    ),
                    "status": "ACTIVE",
                    "taskDefinition": (
                        "arn:aws:ecs:us-east-1:123456789012:task-definition/test-task:1"
                    ),
                }
            ]
        }

        # Mock other responses
        mock_tags_response = {"tags": [{"key": "Environment", "value": "test"}]}
        mock_tasks_response = {"taskArns": ["task-arn-1"]}

        # Mock task definition
        mock_task_definition = {
            "family": "test-task",
            "revision": 1,
            "containerDefinitions": [{"name": "test-container", "image": "nginx:latest"}],
        }

        mock_find_task_defs.return_value = [mock_task_definition]

        # Configure mock to return different responses based on operation
        def mock_ecs_operation(operation, params):
            if operation == "ListServices":
                return mock_list_services_response
            elif operation == "DescribeServices":
                return mock_describe_services_response
            elif operation == "ListTagsForResource":
                return mock_tags_response
            elif operation == "ListTasks":
                return mock_tasks_response
            else:
                return {"error": "Unknown operation"}

        mock_ecs_api.side_effect = mock_ecs_operation

        # Call the method
        result = await self.data_adapter.collect_service_data("test-cluster")

        # Verify the result
        assert result["status"] == "success"
        assert result["cluster_name"] == "test-cluster"
        assert len(result["services"]) == 1

        service_data = result["services"][0]
        assert service_data["service"]["serviceName"] == "test-service"
        assert service_data["task_definition"]["family"] == "test-task"
        assert len(service_data["tags"]) == 1
        assert service_data["tags"][0]["key"] == "Environment"
        assert len(service_data["running_tasks"]) == 1

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.ecs_api_operation")
    async def test_collect_service_data_no_services(self, mock_ecs_api):
        """Test service data collection when no services exist."""
        # Mock empty service list response
        mock_ecs_api.return_value = {"serviceArns": []}

        # Call the method
        result = await self.data_adapter.collect_service_data("test-cluster")

        # Verify the result
        assert result["status"] == "success"
        assert result["cluster_name"] == "test-cluster"
        assert result["services"] == []

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.ecs_api_operation")
    async def test_collect_service_data_specific_service(self, mock_ecs_api):
        """Test service data collection for a specific service."""
        # Mock service describe response
        mock_describe_services_response = {
            "services": [
                {
                    "serviceName": "specific-service",
                    "serviceArn": (
                        "arn:aws:ecs:us-east-1:123456789012:service/test-cluster/specific-service"
                    ),
                    "status": "ACTIVE",
                }
            ]
        }

        # Mock other responses
        mock_tags_response = {"tags": []}
        mock_tasks_response = {"taskArns": []}

        # Configure mock to return different responses based on operation
        def mock_ecs_operation(operation, params):
            if operation == "DescribeServices":
                return mock_describe_services_response
            elif operation == "ListTagsForResource":
                return mock_tags_response
            elif operation == "ListTasks":
                return mock_tasks_response
            else:
                return {"error": "Unknown operation"}

        mock_ecs_api.side_effect = mock_ecs_operation

        # Call the method with specific service name
        result = await self.data_adapter.collect_service_data("test-cluster", "specific-service")

        # Verify the result
        assert result["status"] == "success"
        assert result["cluster_name"] == "test-cluster"
        assert len(result["services"]) == 1
        assert result["services"][0]["service"]["serviceName"] == "specific-service"

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.fetch_network_configuration")
    async def test_collect_network_data_success(self, mock_fetch_network):
        """Test successful network data collection."""
        # Mock network configuration response
        mock_network_response = {
            "status": "success",
            "data": {
                "vpc_ids": ["vpc-12345"],
                "timestamp": "2024-01-01T00:00:00Z",
                "raw_resources": {
                    "vpcs": {
                        "vpc-12345": {
                            "VpcId": "vpc-12345",
                            "CidrBlock": "10.0.0.0/16",
                            "State": "available",
                        }
                    },
                    "subnets": {
                        "subnet-12345": {
                            "SubnetId": "subnet-12345",
                            "VpcId": "vpc-12345",
                            "CidrBlock": "10.0.1.0/24",
                        }
                    },
                    "security_groups": {
                        "sg-12345": {
                            "GroupId": "sg-12345",
                            "GroupName": "default",
                            "VpcId": "vpc-12345",
                        }
                    },
                    "route_tables": {},
                    "network_interfaces": {},
                    "nat_gateways": {},
                    "internet_gateways": {},
                    "load_balancers": {},
                    "target_groups": {},
                },
            },
        }

        mock_fetch_network.return_value = mock_network_response

        # Call the method
        result = await self.data_adapter.collect_network_data("test-cluster")

        # Verify the result
        assert result["status"] == "success"
        assert result["cluster_name"] == "test-cluster"

        network_data = result["network_data"]
        assert network_data["vpc_ids"] == ["vpc-12345"]
        assert network_data["timestamp"] == "2024-01-01T00:00:00Z"
        assert "vpc-12345" in network_data["vpcs"]
        assert "subnet-12345" in network_data["subnets"]
        assert "sg-12345" in network_data["security_groups"]

        # Verify fetch_network_configuration was called correctly
        mock_fetch_network.assert_called_once_with(cluster_name="test-cluster", vpc_id=None)

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.fetch_network_configuration")
    async def test_collect_network_data_error(self, mock_fetch_network):
        """Test network data collection when fetch_network_configuration returns error."""
        # Mock error response
        mock_network_response = {"status": "error", "error": "VPC not found"}

        mock_fetch_network.return_value = mock_network_response

        # Call the method
        result = await self.data_adapter.collect_network_data("test-cluster", "vpc-nonexistent")

        # Verify the result
        assert "error" in result
        assert "VPC not found" in result["error"]
        assert result["cluster_name"] == "test-cluster"
        assert result["network_data"] == {}

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.fetch_network_configuration")
    async def test_collect_network_data_exception(self, mock_fetch_network):
        """Test network data collection when exception occurs."""
        # Mock exception
        mock_fetch_network.side_effect = Exception("Network timeout")

        # Call the method
        result = await self.data_adapter.collect_network_data("test-cluster")

        # Verify the result
        assert "error" in result
        assert "Network timeout" in result["error"]
        assert result["cluster_name"] == "test-cluster"
        assert result["network_data"] == {}

    @pytest.mark.anyio
    async def test_adapt_to_security_format_success(self):
        """Test successful data adaptation to security format."""
        # Mock the individual collection methods
        with (
            patch.object(self.data_adapter, "collect_cluster_data") as mock_cluster,
            patch.object(self.data_adapter, "collect_service_data") as mock_service,
            patch.object(self.data_adapter, "collect_network_data") as mock_network,
        ):
            # Mock successful responses
            mock_cluster.return_value = {
                "cluster": {"clusterName": "test-cluster"},
                "capacity_providers": [{"name": "FARGATE"}],
                "tags": [{"key": "Environment", "value": "test"}],
                "status": "success",
            }

            mock_service.return_value = {
                "services": [{"service": {"serviceName": "test-service"}}],
                "status": "success",
            }

            mock_network.return_value = {
                "network_data": {"vpcs": {"vpc-12345": {}}},
                "status": "success",
            }

            # Call the method
            result = await self.data_adapter.adapt_to_security_format("test-cluster", "us-east-1")

            # Verify the result structure
            assert "us-east-1" in result
            assert "clusters" in result["us-east-1"]
            assert "test-cluster" in result["us-east-1"]["clusters"]

            cluster_data = result["us-east-1"]["clusters"]["test-cluster"]
            assert cluster_data["cluster"]["clusterName"] == "test-cluster"
            assert len(cluster_data["capacity_providers"]) == 1
            assert len(cluster_data["services"]) == 1
            assert "vpc-12345" in cluster_data["network_data"]["vpcs"]

    @pytest.mark.anyio
    async def test_adapt_to_security_format_with_errors(self):
        """Test data adaptation when some collection methods return errors."""
        # Mock the individual collection methods with some errors
        with (
            patch.object(self.data_adapter, "collect_cluster_data") as mock_cluster,
            patch.object(self.data_adapter, "collect_service_data") as mock_service,
            patch.object(self.data_adapter, "collect_network_data") as mock_network,
        ):
            # Mock responses with some errors
            mock_cluster.return_value = {
                "error": "Access denied for cluster",
                "cluster": {},
                "capacity_providers": [],
                "tags": [],
            }

            mock_service.return_value = {"services": [], "status": "success"}

            mock_network.return_value = {
                "error": "Network configuration failed",
                "network_data": {},
            }

            # Call the method
            result = await self.data_adapter.adapt_to_security_format("test-cluster", "us-east-1")

            # Verify the result structure and errors
            assert "us-east-1" in result
            cluster_data = result["us-east-1"]["clusters"]["test-cluster"]
            assert "errors" in cluster_data
            assert len(cluster_data["errors"]) == 2
            assert "Cluster data: Access denied for cluster" in cluster_data["errors"]
            assert "Network data: Network configuration failed" in cluster_data["errors"]

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.ecs_api_operation")
    async def test_collect_cluster_data_capacity_providers_error(self, mock_ecs_api):
        """Test cluster data collection when capacity providers API returns error."""
        # Mock successful cluster response but failed capacity providers
        mock_cluster_response = {
            "clusters": [
                {
                    "clusterName": "test-cluster",
                    "clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster",
                    "status": "ACTIVE",
                }
            ]
        }

        mock_capacity_providers_error = {"error": "Access denied", "status": "failed"}

        # Configure mock to return different responses based on operation
        def mock_ecs_operation(operation, params):
            if operation == "DescribeClusters":
                return mock_cluster_response
            elif operation == "DescribeCapacityProviders":
                return mock_capacity_providers_error
            else:
                return {"error": "Unknown operation"}

        mock_ecs_api.side_effect = mock_ecs_operation

        # Call the method
        result = await self.data_adapter.collect_cluster_data("test-cluster", "us-east-1")

        # Verify the result - should succeed but with empty capacity providers
        assert result["status"] == "success"
        assert result["cluster_name"] == "test-cluster"
        assert result["capacity_providers"] == []  # Should be empty due to error

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.ecs_api_operation")
    async def test_collect_service_data_list_services_error(self, mock_ecs_api):
        """Test service data collection when ListServices returns error."""
        # Mock error response for ListServices
        mock_ecs_api.return_value = {"error": "Access denied", "status": "failed"}

        # Call the method
        result = await self.data_adapter.collect_service_data("test-cluster")

        # Verify the result - should succeed with empty services
        assert result["status"] == "success"
        assert result["cluster_name"] == "test-cluster"
        assert result["services"] == []

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.ecs_api_operation")
    async def test_collect_service_data_describe_services_error(self, mock_ecs_api):
        """Test service data collection when DescribeServices returns error."""

        # Mock successful list but failed describe
        def mock_ecs_operation(operation, params):
            if operation == "ListServices":
                return {
                    "serviceArns": [
                        "arn:aws:ecs:us-east-1:123456789012:service/test-cluster/test-service"
                    ]
                }
            elif operation == "DescribeServices":
                return {"error": "Service not found", "status": "failed"}
            else:
                return {"error": "Unknown operation"}

        mock_ecs_api.side_effect = mock_ecs_operation

        # Call the method
        result = await self.data_adapter.collect_service_data("test-cluster")

        # Verify the result - should succeed but with no services due to describe error
        assert result["status"] == "success"
        assert result["cluster_name"] == "test-cluster"
        assert result["services"] == []  # Should be empty due to describe error

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.find_task_definitions")
    @patch("awslabs.ecs_mcp_server.api.security_analysis.ecs_api_operation")
    async def test_collect_service_data_with_task_definition_fallback(
        self, mock_ecs_api, mock_find_task_defs
    ):
        """Test service data collection with task definition fallback."""
        # Mock service responses
        mock_list_services_response = {
            "serviceArns": ["arn:aws:ecs:us-east-1:123456789012:service/test-cluster/test-service"]
        }

        mock_describe_services_response = {
            "services": [
                {
                    "serviceName": "test-service",
                    "serviceArn": (
                        "arn:aws:ecs:us-east-1:123456789012:service/test-cluster/test-service"
                    ),
                    "status": "ACTIVE",
                    "taskDefinition": (
                        "arn:aws:ecs:us-east-1:123456789012:task-definition/test-task:1"
                    ),
                }
            ]
        }

        # Mock empty task definitions from find_task_definitions (to trigger fallback)
        mock_find_task_defs.return_value = []

        # Mock task definition response for fallback
        mock_task_def_response = {
            "taskDefinition": {
                "family": "test-task",
                "revision": 1,
                "containerDefinitions": [{"name": "test-container", "image": "nginx:latest"}],
            }
        }

        # Configure mock to return different responses based on operation
        def mock_ecs_operation(operation, params):
            if operation == "ListServices":
                return mock_list_services_response
            elif operation == "DescribeServices":
                return mock_describe_services_response
            elif operation == "DescribeTaskDefinition":
                return mock_task_def_response
            elif operation == "ListTagsForResource":
                return {"tags": []}
            elif operation == "ListTasks":
                return {"taskArns": []}
            else:
                return {"error": "Unknown operation"}

        mock_ecs_api.side_effect = mock_ecs_operation

        # Call the method
        result = await self.data_adapter.collect_service_data("test-cluster")

        # Verify the result
        assert result["status"] == "success"
        assert len(result["services"]) == 1

        service_data = result["services"][0]
        assert service_data["service"]["serviceName"] == "test-service"
        assert service_data["task_definition"]["family"] == "test-task"

    @pytest.mark.anyio
    async def test_adapt_to_security_format_exception(self):
        """Test data adaptation when an exception occurs."""
        # Mock the collect_cluster_data to raise an exception
        with patch.object(self.data_adapter, "collect_cluster_data") as mock_cluster:
            mock_cluster.side_effect = Exception("Unexpected error")

            # Call the method
            result = await self.data_adapter.adapt_to_security_format("test-cluster", "us-east-1")

            # Verify the result contains error information
            assert "us-east-1" in result
            assert "error" in result["us-east-1"]
            assert "Unexpected error" in result["us-east-1"]["error"]

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.find_task_definitions")
    @patch("awslabs.ecs_mcp_server.api.security_analysis.ecs_api_operation")
    async def test_collect_service_data_service_exception(self, mock_ecs_api, mock_find_task_defs):
        """Test service data collection when an exception occurs during service processing."""
        # Mock service list response
        mock_list_services_response = {
            "serviceArns": ["arn:aws:ecs:us-east-1:123456789012:service/test-cluster/test-service"]
        }

        # Mock find_task_definitions to raise an exception
        mock_find_task_defs.side_effect = Exception("Task definition error")

        # Configure mock to return different responses based on operation
        def mock_ecs_operation(operation, params):
            if operation == "ListServices":
                return mock_list_services_response
            elif operation == "DescribeServices":
                return {
                    "services": [
                        {
                            "serviceName": "test-service",
                            "serviceArn": (
                                "arn:aws:ecs:us-east-1:123456789012:service/test-cluster/test-service"
                            ),
                            "status": "ACTIVE",
                        }
                    ]
                }
            else:
                return {"tags": []}

        mock_ecs_api.side_effect = mock_ecs_operation

        # Call the method
        result = await self.data_adapter.collect_service_data("test-cluster")

        # Verify the result - should succeed but skip the problematic service
        assert result["status"] == "success"
        assert result["cluster_name"] == "test-cluster"
        assert result["services"] == []  # Should be empty due to exception

    @pytest.mark.anyio
    async def test_adapt_to_security_format_service_error(self):
        """Test data adaptation when service data collection returns error."""
        # Mock the individual collection methods
        with (
            patch.object(self.data_adapter, "collect_cluster_data") as mock_cluster,
            patch.object(self.data_adapter, "collect_service_data") as mock_service,
            patch.object(self.data_adapter, "collect_network_data") as mock_network,
        ):
            # Mock responses with service error
            mock_cluster.return_value = {
                "cluster": {"clusterName": "test-cluster"},
                "capacity_providers": [],
                "tags": [],
                "status": "success",
            }

            mock_service.return_value = {"error": "Service access denied", "services": []}

            mock_network.return_value = {"network_data": {"vpcs": {}}, "status": "success"}

            # Call the method
            result = await self.data_adapter.adapt_to_security_format("test-cluster", "us-east-1")

            # Verify the result structure and errors
            assert "us-east-1" in result
            cluster_data = result["us-east-1"]["clusters"]["test-cluster"]
            assert "errors" in cluster_data
            assert len(cluster_data["errors"]) == 1
            assert "Service data: Service access denied" in cluster_data["errors"]


class TestSecurityAnalyzer:
    """Tests for the SecurityAnalyzer class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.security_analyzer = SecurityAnalyzer()

    def test_analyze_empty_data(self):
        """Test analysis with empty data."""
        result = self.security_analyzer.analyze({})

        assert result["recommendations"] == []
        assert result["total_issues"] == 0
        assert result["analysis_summary"]["total_recommendations"] == 0
        assert "timestamp" in result

    def test_analyze_data_with_errors(self):
        """Test analysis with data containing errors."""
        ecs_data = {"us-east-1": {"error": "Region access denied"}}

        result = self.security_analyzer.analyze(ecs_data)

        assert result["recommendations"] == []
        assert result["total_issues"] == 0

    def test_analyze_cluster_security_container_insights_disabled(self):
        """Test cluster security analysis when Container Insights is disabled."""
        cluster_data = {
            "cluster": {
                "clusterName": "test-cluster",
                "settings": [],  # No Container Insights setting
            }
        }

        recommendations = self.security_analyzer._analyze_cluster_security(
            "test-cluster", cluster_data, "us-east-1"
        )

        assert len(recommendations) >= 1
        container_insights_rec = next(
            (rec for rec in recommendations if "Container Insights" in rec["title"]), None
        )
        assert container_insights_rec is not None
        assert container_insights_rec["severity"] == "Medium"
        assert container_insights_rec["category"] == "monitoring"

    def test_analyze_cluster_security_container_insights_enabled(self):
        """Test cluster security analysis when Container Insights is enabled."""
        cluster_data = {
            "cluster": {
                "clusterName": "test-cluster",
                "settings": [{"name": "containerInsights", "value": "enabled"}],
            }
        }

        recommendations = self.security_analyzer._analyze_cluster_security(
            "test-cluster", cluster_data, "us-east-1"
        )

        # Should not have Container Insights recommendation
        container_insights_rec = next(
            (rec for rec in recommendations if "Container Insights" in rec["title"]), None
        )
        assert container_insights_rec is None

    def test_analyze_cluster_security_execute_command_not_configured(self):
        """Test cluster security analysis when execute command is not configured."""
        cluster_data = {
            "cluster": {
                "clusterName": "test-cluster",
                "settings": [],
                "configuration": {},  # No execute command configuration
            }
        }

        recommendations = self.security_analyzer._analyze_cluster_security(
            "test-cluster", cluster_data, "us-east-1"
        )

        execute_command_rec = next(
            (rec for rec in recommendations if "Execute Command Security" in rec["title"]), None
        )
        assert execute_command_rec is not None
        assert execute_command_rec["severity"] == "Medium"
        assert execute_command_rec["category"] == "security"

    def test_analyze_cluster_security_execute_command_logging_not_configured(self):
        """Test cluster security analysis when execute command logging is not configured."""
        cluster_data = {
            "cluster": {
                "clusterName": "test-cluster",
                "settings": [],
                "configuration": {
                    "executeCommandConfiguration": {
                        "logging": "DEFAULT"  # Not OVERRIDE
                    }
                },
            }
        }

        recommendations = self.security_analyzer._analyze_cluster_security(
            "test-cluster", cluster_data, "us-east-1"
        )

        logging_rec = next(
            (rec for rec in recommendations if "Execute Command Audit Logging" in rec["title"]),
            None,
        )
        assert logging_rec is not None
        assert logging_rec["severity"] == "Medium"
        assert logging_rec["category"] == "monitoring"

    def test_analyze_cluster_security_properly_configured(self):
        """Test cluster security analysis when cluster is properly configured."""
        cluster_data = {
            "cluster": {
                "clusterName": "test-cluster",
                "status": "ACTIVE",
                "settings": [{"name": "containerInsights", "value": "enabled"}],
                "configuration": {
                    "executeCommandConfiguration": {
                        "logging": "OVERRIDE",
                        "kmsKeyId": (
                            "arn:aws:kms:us-east-1:123456789012:key/"
                            "12345678-1234-1234-1234-123456789012"
                        ),
                    }
                },
            }
        }

        recommendations = self.security_analyzer._analyze_cluster_security(
            "test-cluster", cluster_data, "us-east-1"
        )

        # Should have no recommendations for a properly configured cluster
        assert len(recommendations) == 0

    def test_analyze_full_ecs_data(self):
        """Test full analysis with complete ECS data."""
        ecs_data = {
            "us-east-1": {
                "clusters": {
                    "cluster-1": {
                        "cluster": {
                            "clusterName": "cluster-1",
                            "settings": [],  # Container Insights disabled
                        }
                    },
                    "cluster-2": {
                        "cluster": {
                            "clusterName": "cluster-2",
                            "settings": [{"name": "containerInsights", "value": "enabled"}],
                            "configuration": {},  # Execute command not configured
                        }
                    },
                }
            },
            "us-west-2": {"clusters": {"cluster-3": {"error": "Access denied"}}},
        }

        result = self.security_analyzer.analyze(ecs_data)

        # Should have recommendations from cluster-1 and cluster-2
        assert result["total_issues"] >= 2
        assert len(result["recommendations"]) >= 2

        # Check analysis summary
        summary = result["analysis_summary"]
        assert summary["total_recommendations"] >= 2
        assert "Medium" in summary["severity_breakdown"]
        assert "monitoring" in summary["category_breakdown"]
        assert "security" in summary["category_breakdown"]

    def test_generate_analysis_summary(self):
        """Test analysis summary generation."""
        recommendations = [
            {"severity": "High", "category": "security"},
            {"severity": "Medium", "category": "monitoring"},
            {"severity": "Medium", "category": "security"},
            {"severity": "Low", "category": "compliance"},
        ]

        summary = self.security_analyzer._generate_analysis_summary(recommendations)

        assert summary["total_recommendations"] == 4
        assert summary["severity_breakdown"]["High"] == 1
        assert summary["severity_breakdown"]["Medium"] == 2
        assert summary["severity_breakdown"]["Low"] == 1
        assert summary["category_breakdown"]["security"] == 2
        assert summary["category_breakdown"]["monitoring"] == 1
        assert summary["category_breakdown"]["compliance"] == 1


class TestAnalyzeEcsSecurity:
    """Tests for the analyze_ecs_security function."""

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.find_clusters")
    async def test_analyze_ecs_security_success(self, mock_find_clusters):
        """Test successful ECS security analysis."""
        # Mock cluster discovery
        mock_find_clusters.return_value = ["test-cluster"]

        # Mock DataAdapter and SecurityAnalyzer
        with (
            patch("awslabs.ecs_mcp_server.api.security_analysis.DataAdapter") as mock_adapter_class,
            patch(
                "awslabs.ecs_mcp_server.api.security_analysis.SecurityAnalyzer"
            ) as mock_analyzer_class,
        ):
            # Mock adapter instance and methods
            mock_adapter = AsyncMock()
            mock_adapter.adapt_to_security_format.return_value = {
                "us-east-1": {
                    "clusters": {"test-cluster": {"cluster": {"clusterName": "test-cluster"}}}
                }
            }
            mock_adapter_class.return_value = mock_adapter

            # Mock analyzer instance and methods
            mock_analyzer = MagicMock()
            mock_analyzer.analyze.return_value = {
                "recommendations": [{"title": "Test recommendation", "severity": "Medium"}],
                "total_issues": 1,
                "analysis_summary": {"total_recommendations": 1},
            }
            mock_analyzer_class.return_value = mock_analyzer

            # Call the function
            result = await analyze_ecs_security()

            # Verify the result
            assert result["status"] == "success"
            assert result["total_issues"] == 1
            assert len(result["recommendations"]) == 1
            assert result["regions_analyzed"] == ["us-east-1"]
            assert result["clusters_analyzed"] == "all_discovered"
            assert result["analysis_scope"] == "basic"

            # Verify mocks were called
            mock_find_clusters.assert_called_once()
            mock_adapter.adapt_to_security_format.assert_called_once_with(
                "test-cluster", "us-east-1"
            )
            mock_analyzer.analyze.assert_called_once()

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.find_clusters")
    async def test_analyze_ecs_security_specific_clusters_and_regions(self, mock_find_clusters):
        """Test ECS security analysis with specific clusters and regions."""
        # Mock DataAdapter and SecurityAnalyzer
        with (
            patch("awslabs.ecs_mcp_server.api.security_analysis.DataAdapter") as mock_adapter_class,
            patch(
                "awslabs.ecs_mcp_server.api.security_analysis.SecurityAnalyzer"
            ) as mock_analyzer_class,
        ):
            # Mock adapter instance
            mock_adapter = AsyncMock()
            mock_adapter.adapt_to_security_format.return_value = {
                "us-west-2": {
                    "clusters": {
                        "specific-cluster": {"cluster": {"clusterName": "specific-cluster"}}
                    }
                }
            }
            mock_adapter_class.return_value = mock_adapter

            # Mock analyzer instance
            mock_analyzer = MagicMock()
            mock_analyzer.analyze.return_value = {
                "recommendations": [],
                "total_issues": 0,
                "analysis_summary": {"total_recommendations": 0},
            }
            mock_analyzer_class.return_value = mock_analyzer

            # Call the function with specific parameters
            result = await analyze_ecs_security(
                cluster_names=["specific-cluster"],
                regions=["us-west-2"],
                analysis_scope="comprehensive",
            )

            # Verify the result
            assert result["status"] == "success"
            assert result["regions_analyzed"] == ["us-west-2"]
            assert result["clusters_analyzed"] == ["specific-cluster"]
            assert result["analysis_scope"] == "comprehensive"

            # Verify find_clusters was not called (specific clusters provided)
            mock_find_clusters.assert_not_called()
            mock_adapter.adapt_to_security_format.assert_called_once_with(
                "specific-cluster", "us-west-2"
            )

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.find_clusters")
    async def test_analyze_ecs_security_cluster_error(self, mock_find_clusters):
        """Test ECS security analysis when cluster data collection fails."""
        # Mock cluster discovery
        mock_find_clusters.return_value = ["error-cluster"]

        # Mock DataAdapter with error
        with (
            patch("awslabs.ecs_mcp_server.api.security_analysis.DataAdapter") as mock_adapter_class,
            patch(
                "awslabs.ecs_mcp_server.api.security_analysis.SecurityAnalyzer"
            ) as mock_analyzer_class,
        ):
            # Mock adapter instance that raises exception
            mock_adapter = AsyncMock()
            mock_adapter.adapt_to_security_format.side_effect = Exception("Cluster access denied")
            mock_adapter_class.return_value = mock_adapter

            # Mock analyzer instance
            mock_analyzer = MagicMock()
            mock_analyzer.analyze.return_value = {
                "recommendations": [],
                "total_issues": 0,
                "analysis_summary": {"total_recommendations": 0},
            }
            mock_analyzer_class.return_value = mock_analyzer

            # Call the function
            result = await analyze_ecs_security()

            # Verify the result still succeeds but with error data
            assert result["status"] == "success"
            assert result["total_issues"] == 0

            # Verify error handling was called
            mock_adapter.adapt_to_security_format.assert_called_once()

    @pytest.mark.anyio
    async def test_analyze_ecs_security_general_exception(self):
        """Test ECS security analysis when general exception occurs at top level."""
        # Mock DataAdapter to raise exception during initialization
        with patch(
            "awslabs.ecs_mcp_server.api.security_analysis.DataAdapter"
        ) as mock_adapter_class:
            mock_adapter_class.side_effect = Exception("General error")

            # Call the function
            result = await analyze_ecs_security()

            # Verify error response
            assert result["status"] == "error"
            assert "General error" in result["error"]
            assert "timestamp" in result

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.find_clusters")
    async def test_analyze_ecs_security_multiple_regions(self, mock_find_clusters):
        """Test ECS security analysis across multiple regions."""
        # Mock cluster discovery
        mock_find_clusters.return_value = ["cluster-1", "cluster-2"]

        # Mock DataAdapter and SecurityAnalyzer
        with (
            patch("awslabs.ecs_mcp_server.api.security_analysis.DataAdapter") as mock_adapter_class,
            patch(
                "awslabs.ecs_mcp_server.api.security_analysis.SecurityAnalyzer"
            ) as mock_analyzer_class,
        ):
            # Mock adapter instance
            mock_adapter = AsyncMock()

            def mock_adapt_to_security_format(cluster_name, region):
                return {
                    region: {"clusters": {cluster_name: {"cluster": {"clusterName": cluster_name}}}}
                }

            mock_adapter.adapt_to_security_format.side_effect = mock_adapt_to_security_format
            mock_adapter_class.return_value = mock_adapter

            # Mock analyzer instance
            mock_analyzer = MagicMock()
            mock_analyzer.analyze.return_value = {
                "recommendations": [],
                "total_issues": 0,
                "analysis_summary": {"total_recommendations": 0},
            }
            mock_analyzer_class.return_value = mock_analyzer

            # Call the function with multiple regions
            result = await analyze_ecs_security(regions=["us-east-1", "us-west-2"])

            # Verify the result
            assert result["status"] == "success"
            assert result["regions_analyzed"] == ["us-east-1", "us-west-2"]

            # Verify adapter was called for each cluster in each region
            assert mock_adapter.adapt_to_security_format.call_count == 4  # 2 clusters × 2 regions

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.find_clusters")
    async def test_analyze_ecs_security_no_clusters_found(self, mock_find_clusters):
        """Test ECS security analysis when no clusters are found."""
        # Mock empty cluster discovery
        mock_find_clusters.return_value = []

        # Mock SecurityAnalyzer
        with patch(
            "awslabs.ecs_mcp_server.api.security_analysis.SecurityAnalyzer"
        ) as mock_analyzer_class:
            # Mock analyzer instance
            mock_analyzer = MagicMock()
            mock_analyzer.analyze.return_value = {
                "recommendations": [],
                "total_issues": 0,
                "analysis_summary": {"total_recommendations": 0},
            }
            mock_analyzer_class.return_value = mock_analyzer

            # Call the function
            result = await analyze_ecs_security()

            # Verify the result
            assert result["status"] == "success"
            assert result["total_issues"] == 0
            assert result["regions_analyzed"] == ["us-east-1"]
            assert result["clusters_analyzed"] == "all_discovered"

            # Verify analyzer was still called with empty data
            mock_analyzer.analyze.assert_called_once()

    @pytest.mark.anyio
    @patch("awslabs.ecs_mcp_server.api.security_analysis.find_clusters")
    async def test_analyze_ecs_security_region_exception(self, mock_find_clusters):
        """Test ECS security analysis when region-level exception occurs."""
        # Mock cluster discovery to raise exception
        mock_find_clusters.side_effect = Exception("Region access error")

        # Mock SecurityAnalyzer
        with patch(
            "awslabs.ecs_mcp_server.api.security_analysis.SecurityAnalyzer"
        ) as mock_analyzer_class:
            # Mock analyzer instance
            mock_analyzer = MagicMock()
            mock_analyzer.analyze.return_value = {
                "recommendations": [],
                "total_issues": 0,
                "analysis_summary": {"total_recommendations": 0},
            }
            mock_analyzer_class.return_value = mock_analyzer

            # Call the function
            result = await analyze_ecs_security()

            # Verify the result still succeeds but with region error data
            assert result["status"] == "success"
            assert result["total_issues"] == 0

            # Verify analyzer was called with error data
            mock_analyzer.analyze.assert_called_once()
            call_args = mock_analyzer.analyze.call_args[0][0]
            assert "us-east-1" in call_args
            assert "error" in call_args["us-east-1"]
            assert "Region access error" in call_args["us-east-1"]["error"]
