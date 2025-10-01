"""
Unit tests for the Security Analysis module.
"""

from unittest.mock import MagicMock, patch

from awslabs.ecs_mcp_server.modules import security_analysis


class TestSecurityAnalysisModule:
    """Tests for the security analysis module functions."""

    @patch("awslabs.ecs_mcp_server.modules.security_analysis.ECSSecurityAnalyzer")
    def test_analyze_cluster_security_success(self, mock_analyzer_class):
        """Test successful cluster security analysis."""
        # Setup mock analyzer
        mock_analyzer = MagicMock()
        mock_analyzer.analyze_cluster_security.return_value = {
            "status": "success",
            "cluster_name": "test-cluster",
            "findings": [],
        }
        mock_analyzer_class.return_value = mock_analyzer

        # Call function
        result = security_analysis.analyze_cluster_security("test-cluster")

        # Verify calls
        mock_analyzer_class.assert_called_once_with(region_name="us-east-1")
        mock_analyzer.analyze_cluster_security.assert_called_once_with("test-cluster")

        # Verify result
        assert result["status"] == "success"
        assert result["cluster_name"] == "test-cluster"

    @patch("awslabs.ecs_mcp_server.modules.security_analysis.ECSSecurityAnalyzer")
    def test_analyze_cluster_security_with_region_and_profile(self, mock_analyzer_class):
        """Test cluster security analysis with region and profile."""
        # Setup mock analyzer
        mock_analyzer = MagicMock()
        mock_analyzer.analyze_cluster_security.return_value = {
            "status": "success",
            "cluster_name": "test-cluster",
            "findings": [],
        }
        mock_analyzer_class.return_value = mock_analyzer

        # Call function with region and profile
        result = security_analysis.analyze_cluster_security(
            "test-cluster", region="us-west-2", profile="dev"
        )

        # Verify calls
        mock_analyzer_class.assert_called_once_with(region_name="us-west-2")

        # Verify result
        assert result["status"] == "success"

    @patch("awslabs.ecs_mcp_server.modules.security_analysis.ECSSecurityAnalyzer")
    def test_analyze_cluster_security_exception(self, mock_analyzer_class):
        """Test cluster security analysis with exception."""
        # Setup mock to raise exception
        mock_analyzer_class.side_effect = Exception("AWS connection error")

        # Call function
        result = security_analysis.analyze_cluster_security("test-cluster")

        # Verify error handling
        assert result["status"] == "error"
        assert "AWS connection error" in result["message"]
        assert result["cluster_name"] == "test-cluster"

    @patch("awslabs.ecs_mcp_server.modules.security_analysis.ECSSecurityAnalyzer")
    def test_analyze_service_security_success(self, mock_analyzer_class):
        """Test successful service security analysis."""
        # Setup mock analyzer
        mock_analyzer = MagicMock()
        mock_analyzer.analyze_service_security.return_value = {
            "status": "success",
            "cluster_name": "test-cluster",
            "service_name": "test-service",
            "findings": [],
        }
        mock_analyzer_class.return_value = mock_analyzer

        # Call function
        result = security_analysis.analyze_service_security("test-cluster", "test-service")

        # Verify calls
        mock_analyzer.analyze_service_security.assert_called_once_with(
            "test-cluster", "test-service"
        )

        # Verify result
        assert result["status"] == "success"
        assert result["service_name"] == "test-service"

    @patch("awslabs.ecs_mcp_server.modules.security_analysis.ECSSecurityAnalyzer")
    def test_analyze_task_definition_security_success(self, mock_analyzer_class):
        """Test successful task definition security analysis."""
        # Setup mock analyzer
        mock_analyzer = MagicMock()
        mock_analyzer.analyze_task_definition_security.return_value = {
            "status": "success",
            "task_definition_arn": "test-task:1",
            "findings": [],
        }
        mock_analyzer_class.return_value = mock_analyzer

        # Call function
        result = security_analysis.analyze_task_definition_security("test-task:1")

        # Verify calls
        mock_analyzer.analyze_task_definition_security.assert_called_once_with("test-task:1")

        # Verify result
        assert result["status"] == "success"
        assert result["task_definition_arn"] == "test-task:1"

    @patch("awslabs.ecs_mcp_server.modules.security_analysis.ECSSecurityAnalyzer")
    def test_analyze_comprehensive_security_success(self, mock_analyzer_class):
        """Test successful comprehensive security analysis."""
        # Setup mock analyzer
        mock_analyzer = MagicMock()
        mock_analyzer.analyze_comprehensive_security.return_value = {
            "status": "success",
            "cluster_name": "test-cluster",
            "total_findings": 5,
            "severity_summary": {"High": 2, "Medium": 2, "Low": 1},
            "findings": [],
        }
        mock_analyzer_class.return_value = mock_analyzer

        # Call function
        result = security_analysis.analyze_comprehensive_security("test-cluster")

        # Verify calls
        mock_analyzer.analyze_comprehensive_security.assert_called_once_with("test-cluster")

        # Verify result
        assert result["status"] == "success"
        assert result["total_findings"] == 5
        assert result["severity_summary"]["High"] == 2

    @patch("awslabs.ecs_mcp_server.modules.security_analysis.ECSSecurityAnalyzer")
    def test_generate_security_report_success(self, mock_analyzer_class):
        """Test successful security report generation."""
        # Setup mock analyzer
        mock_analyzer = MagicMock()
        mock_analyzer.generate_security_report.return_value = {
            "cluster_name": "test-cluster",
            "report_type": "json",
            "total_findings": 3,
            "findings": [],
        }
        mock_analyzer_class.return_value = mock_analyzer

        # Call function
        result = security_analysis.generate_security_report(
            cluster_name="test-cluster",
            severity_filter=["High"],
            category_filter=["iam"],
            compliance_framework="SOC2",
            include_recommendations=True,
            format_type="json",
        )

        # Verify calls
        mock_analyzer.generate_security_report.assert_called_once_with(
            cluster_name="test-cluster",
            severity_filter=["High"],
            category_filter=["iam"],
            compliance_framework="SOC2",
            include_recommendations=True,
            format_type="json",
        )

        # Verify result
        assert result["cluster_name"] == "test-cluster"
        assert result["total_findings"] == 3

    @patch("awslabs.ecs_mcp_server.modules.security_analysis.ECSSecurityAnalyzer")
    def test_get_security_metrics_success(self, mock_analyzer_class):
        """Test successful security metrics retrieval."""
        # Setup mock analyzer
        mock_analyzer = MagicMock()
        mock_analyzer.get_security_metrics.return_value = {
            "cluster_name": "test-cluster",
            "security_score": 85,
            "risk_level": "Low",
            "total_findings": 2,
        }
        mock_analyzer_class.return_value = mock_analyzer

        # Call function
        result = security_analysis.get_security_metrics("test-cluster")

        # Verify calls
        mock_analyzer.get_security_metrics.assert_called_once_with("test-cluster")

        # Verify result
        assert result["cluster_name"] == "test-cluster"
        assert result["security_score"] == 85
        assert result["risk_level"] == "Low"

    def test_register_module(self):
        """Test module registration with FastMCP."""
        # Create mock FastMCP instance
        mock_mcp = MagicMock()

        # Call register_module
        security_analysis.register_module(mock_mcp)

        # Verify that tools were registered
        # The @mcp.tool() decorator should have been called multiple times
        assert mock_mcp.tool.call_count == 6  # 6 security analysis tools

        # Verify the tool decorator was called (it returns a decorator function)
        mock_mcp.tool.assert_called()


class TestSecurityAnalysisModuleIntegration:
    """Integration tests for the security analysis module."""

    @patch("awslabs.ecs_mcp_server.modules.security_analysis.ECSSecurityAnalyzer")
    def test_full_workflow_comprehensive_analysis(self, mock_analyzer_class):
        """Test full workflow from comprehensive analysis to report generation."""
        # Setup mock analyzer
        mock_analyzer = MagicMock()

        # Mock comprehensive analysis
        comprehensive_result = {
            "status": "success",
            "cluster_name": "prod-cluster",
            "total_findings": 8,
            "severity_summary": {"High": 3, "Medium": 3, "Low": 2},
            "findings": [
                {
                    "severity": "High",
                    "category": "iam",
                    "resource": "Task Definition: web-app:1",
                    "issue": "Missing execution role",
                    "recommendation": "Add execution role",
                    "compliance_frameworks": ["SOC2", "HIPAA"],
                },
                {
                    "severity": "High",
                    "category": "container_security",
                    "resource": "Container: web-container",
                    "issue": "Privileged container detected",
                    "recommendation": "Remove privileged flag",
                    "compliance_frameworks": ["SOC2", "PCI-DSS"],
                },
                {
                    "severity": "Medium",
                    "category": "network_security",
                    "resource": "Service: web-service",
                    "issue": "Missing security group restrictions",
                    "recommendation": "Restrict security group rules",
                    "compliance_frameworks": ["SOC2"],
                },
            ],
        }
        mock_analyzer.analyze_comprehensive_security.return_value = comprehensive_result

        # Mock report generation
        report_result = {
            "cluster_name": "prod-cluster",
            "report_type": "summary",
            "security_posture": "Fair",
            "risk_score": 40,
            "total_findings": 2,  # Filtered to High severity only
            "severity_breakdown": {"High": 2, "Medium": 0, "Low": 0},
        }
        mock_analyzer.generate_security_report.return_value = report_result

        # Mock metrics
        metrics_result = {
            "cluster_name": "prod-cluster",
            "security_score": 40,
            "risk_level": "High",
            "total_findings": 8,
            "severity_distribution": {"High": 3, "Medium": 3, "Low": 2},
        }
        mock_analyzer.get_security_metrics.return_value = metrics_result

        mock_analyzer_class.return_value = mock_analyzer

        # Step 1: Comprehensive analysis
        comprehensive_analysis = security_analysis.analyze_comprehensive_security("prod-cluster")
        assert comprehensive_analysis["status"] == "success"
        assert comprehensive_analysis["total_findings"] == 8

        # Step 2: Generate filtered report
        filtered_report = security_analysis.generate_security_report(
            cluster_name="prod-cluster", severity_filter=["High"], format_type="summary"
        )
        assert filtered_report["security_posture"] == "Fair"
        assert filtered_report["total_findings"] == 2

        # Step 3: Get security metrics
        metrics = security_analysis.get_security_metrics("prod-cluster")
        assert metrics["security_score"] == 40
        assert metrics["risk_level"] == "High"

        # Verify all analyzer methods were called
        mock_analyzer.analyze_comprehensive_security.assert_called_with("prod-cluster")
        mock_analyzer.generate_security_report.assert_called()
        mock_analyzer.get_security_metrics.assert_called_with("prod-cluster")

    @patch("awslabs.ecs_mcp_server.modules.security_analysis.ECSSecurityAnalyzer")
    def test_error_handling_chain(self, mock_analyzer_class):
        """Test error handling across multiple function calls."""
        # Setup analyzer mock to fail on comprehensive analysis
        mock_analyzer = MagicMock()
        mock_analyzer.analyze_comprehensive_security.side_effect = Exception("ECS API Error")
        mock_analyzer_class.return_value = mock_analyzer

        # Test that error is properly handled
        result = security_analysis.analyze_comprehensive_security("test-cluster")

        assert result["status"] == "error"
        assert "ECS API Error" in result["message"]
        assert result["cluster_name"] == "test-cluster"

        # Test that subsequent calls also handle errors properly
        mock_analyzer.generate_security_report.side_effect = Exception("Report generation failed")

        report_result = security_analysis.generate_security_report("test-cluster")
        assert report_result["status"] == "error"
        assert "Report generation failed" in report_result["message"]

    @patch("awslabs.ecs_mcp_server.modules.security_analysis.ECSSecurityAnalyzer")
    def test_analyzer_creation_failure(self, mock_analyzer_class):
        """Test handling of analyzer creation failure."""
        # Mock analyzer creation failure
        mock_analyzer_class.side_effect = Exception("AWS credentials not found")

        # Test all main functions handle analyzer creation failure
        functions_to_test = [
            ("analyze_cluster_security", ("test-cluster",)),
            ("analyze_service_security", ("test-cluster", "test-service")),
            ("analyze_task_definition_security", ("test-task:1",)),
            ("analyze_comprehensive_security", ("test-cluster",)),
            ("generate_security_report", ("test-cluster",)),
            ("get_security_metrics", ("test-cluster",)),
        ]

        for func_name, args in functions_to_test:
            func = getattr(security_analysis, func_name)
            result = func(*args)

            assert result["status"] == "error"
            assert "AWS credentials not found" in result["message"]
