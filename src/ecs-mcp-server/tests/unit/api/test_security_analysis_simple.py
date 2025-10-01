"""
Simplified unit tests for the ECS Security Analysis API module.
"""

from unittest.mock import MagicMock, patch

from awslabs.ecs_mcp_server.api.security_analysis import ECSSecurityAnalyzer


class TestECSSecurityAnalyzerSimple:
    """Simplified tests for the ECS Security Analyzer class."""

    @patch("boto3.client")
    def test_init(self, mock_boto_client):
        """Test ECSSecurityAnalyzer initialization."""
        analyzer = ECSSecurityAnalyzer("us-west-2")

        assert analyzer.region_name == "us-west-2"
        assert analyzer._ecs_client is None  # Lazy initialization
        assert analyzer._ec2_client is None
        assert analyzer._elbv2_client is None

    @patch("boto3.client")
    def test_format_resource_name(self, mock_boto_client):
        """Test _format_resource_name method."""
        analyzer = ECSSecurityAnalyzer("us-east-1")

        result = analyzer._format_resource_name("Cluster", "test-cluster")
        assert result == "Cluster: test-cluster"

    @patch("boto3.client")
    def test_analyze_cluster_security_success(self, mock_boto_client):
        """Test successful cluster security analysis."""
        # Mock ECS client
        mock_ecs_client = MagicMock()
        mock_ecs_client.describe_clusters.return_value = {
            "clusters": [
                {
                    "clusterName": "test-cluster",
                    "status": "ACTIVE",
                    "configuration": {"executeCommandConfiguration": {"logging": "DEFAULT"}},
                    "settings": [],
                }
            ]
        }
        mock_boto_client.return_value = mock_ecs_client

        analyzer = ECSSecurityAnalyzer("us-east-1")
        result = analyzer.analyze_cluster_security("test-cluster")

        assert result["status"] == "success"
        assert result["cluster_name"] == "test-cluster"
        assert "findings" in result
        assert isinstance(result["findings"], list)

    @patch("boto3.client")
    def test_analyze_cluster_security_not_found(self, mock_boto_client):
        """Test cluster security analysis with cluster not found."""
        # Mock ECS client with no clusters
        mock_ecs_client = MagicMock()
        mock_ecs_client.describe_clusters.return_value = {"clusters": []}
        mock_boto_client.return_value = mock_ecs_client

        analyzer = ECSSecurityAnalyzer("us-east-1")
        result = analyzer.analyze_cluster_security("nonexistent-cluster")

        assert result["status"] == "error"
        assert "not found" in result["message"]

    @patch("boto3.client")
    def test_analyze_cluster_security_exception(self, mock_boto_client):
        """Test cluster security analysis with exception."""
        # Mock ECS client to raise exception
        mock_ecs_client = MagicMock()
        mock_ecs_client.describe_clusters.side_effect = Exception("AWS Error")
        mock_boto_client.return_value = mock_ecs_client

        analyzer = ECSSecurityAnalyzer("us-east-1")
        result = analyzer.analyze_cluster_security("test-cluster")

        assert result["status"] == "error"
        assert "AWS Error" in result["message"]

    @patch("boto3.client")
    def test_analyze_task_definition_security_missing_roles(self, mock_boto_client):
        """Test task definition analysis with missing IAM roles."""
        # Mock ECS client
        mock_ecs_client = MagicMock()
        mock_ecs_client.describe_task_definition.return_value = {
            "taskDefinition": {
                "family": "test-task",
                "revision": 1,
                "networkMode": "awsvpc",
                "requiresCompatibilities": ["FARGATE"],
                "cpu": "256",
                "memory": "512",
                "containerDefinitions": [
                    {"name": "test-container", "image": "nginx:latest", "essential": True}
                ],
            }
        }
        mock_boto_client.return_value = mock_ecs_client

        analyzer = ECSSecurityAnalyzer("us-east-1")
        result = analyzer.analyze_task_definition_security("test-task:1")

        assert result["status"] == "success"
        # Should have findings about missing roles
        high_severity_findings = [f for f in result["findings"] if f["severity"] == "High"]
        assert len(high_severity_findings) > 0

        # Check for missing execution role finding (more flexible matching)
        execution_role_findings = [
            f
            for f in high_severity_findings
            if "execution" in f["issue"].lower() and "role" in f["issue"].lower()
        ]
        # If no execution role findings, check for any IAM-related findings
        if len(execution_role_findings) == 0:
            iam_findings = [
                f
                for f in high_severity_findings
                if "iam" in f["issue"].lower() or "role" in f["issue"].lower()
            ]
            assert len(iam_findings) > 0, (
                f"Expected IAM/role findings, got: {[f['issue'] for f in high_severity_findings]}"
            )
        else:
            assert len(execution_role_findings) > 0

    @patch("boto3.client")
    def test_analyze_task_definition_privileged_container(self, mock_boto_client):
        """Test task definition analysis with privileged container."""
        # Mock ECS client
        mock_ecs_client = MagicMock()
        mock_ecs_client.describe_task_definition.return_value = {
            "taskDefinition": {
                "family": "test-task",
                "revision": 1,
                "taskRoleArn": "arn:aws:iam::123456789012:role/task-role",
                "executionRoleArn": "arn:aws:iam::123456789012:role/execution-role",
                "networkMode": "awsvpc",
                "requiresCompatibilities": ["EC2"],
                "containerDefinitions": [
                    {
                        "name": "test-container",
                        "image": "nginx:latest",
                        "essential": True,
                        "privileged": True,
                        "user": "root",
                    }
                ],
            }
        }
        mock_boto_client.return_value = mock_ecs_client

        analyzer = ECSSecurityAnalyzer("us-east-1")
        result = analyzer.analyze_task_definition_security("test-task:1")

        assert result["status"] == "success"
        # Should have findings about privileged container
        high_severity_findings = [f for f in result["findings"] if f["severity"] == "High"]
        privileged_findings = [
            f for f in high_severity_findings if "privileged" in f["issue"].lower()
        ]
        assert len(privileged_findings) > 0

    @patch("boto3.client")
    def test_analyze_task_definition_secrets_in_env(self, mock_boto_client):
        """Test task definition analysis with secrets in environment variables."""
        # Mock ECS client
        mock_ecs_client = MagicMock()
        mock_ecs_client.describe_task_definition.return_value = {
            "taskDefinition": {
                "family": "test-task",
                "revision": 1,
                "taskRoleArn": "arn:aws:iam::123456789012:role/task-role",
                "executionRoleArn": "arn:aws:iam::123456789012:role/execution-role",
                "networkMode": "awsvpc",
                "requiresCompatibilities": ["FARGATE"],
                "containerDefinitions": [
                    {
                        "name": "test-container",
                        "image": "nginx:latest",
                        "essential": True,
                        "environment": [
                            {"name": "API_KEY", "value": "secret-api-key-123"},
                            {"name": "PASSWORD", "value": "my-secret-password"},
                            {"name": "DEBUG", "value": "true"},
                        ],
                    }
                ],
            }
        }
        mock_boto_client.return_value = mock_ecs_client

        analyzer = ECSSecurityAnalyzer("us-east-1")
        result = analyzer.analyze_task_definition_security("test-task:1")

        assert result["status"] == "success"
        # Should have findings about secrets in environment variables
        high_severity_findings = [f for f in result["findings"] if f["severity"] == "High"]
        secret_findings = [
            f
            for f in high_severity_findings
            if "secret" in f["issue"].lower() or "environment" in f["issue"].lower()
        ]
        assert len(secret_findings) > 0

    def test_calculate_risk_level(self):
        """Test risk level calculation."""
        with patch("boto3.client"):
            analyzer = ECSSecurityAnalyzer("us-east-1")

            assert analyzer._calculate_risk_level(95) == "Very Low"
            assert analyzer._calculate_risk_level(85) == "Low"
            assert analyzer._calculate_risk_level(70) == "Medium"
            assert analyzer._calculate_risk_level(50) == "High"
            assert analyzer._calculate_risk_level(30) == "Very High"

    def test_apply_filters(self):
        """Test filtering functionality."""
        with patch("boto3.client"):
            analyzer = ECSSecurityAnalyzer("us-east-1")

            findings = [
                {"severity": "High", "category": "iam", "compliance_frameworks": ["SOC2"]},
                {
                    "severity": "Medium",
                    "category": "container_security",
                    "compliance_frameworks": ["HIPAA"],
                },
                {
                    "severity": "Low",
                    "category": "monitoring",
                    "compliance_frameworks": ["SOC2", "HIPAA"],
                },
            ]

            # Test severity filter
            filtered = analyzer._apply_filters(findings, severity_filter=["High", "Medium"])
            assert len(filtered) == 2

            # Test category filter
            filtered = analyzer._apply_filters(findings, category_filter=["iam"])
            assert len(filtered) == 1
            assert filtered[0]["category"] == "iam"

            # Test compliance framework filter
            filtered = analyzer._apply_filters(findings, compliance_framework="SOC2")
            assert len(filtered) == 2  # High and Low findings have SOC2

            # Test combined filters
            filtered = analyzer._apply_filters(
                findings, severity_filter=["High", "Low"], compliance_framework="SOC2"
            )
            assert len(filtered) == 2

    def test_strip_recommendations(self):
        """Test recommendation stripping functionality."""
        with patch("boto3.client"):
            analyzer = ECSSecurityAnalyzer("us-east-1")

            findings = [
                {
                    "severity": "High",
                    "category": "iam",
                    "issue": "Missing role",
                    "recommendation": "Add IAM role",
                },
                {
                    "severity": "Medium",
                    "category": "container_security",
                    "issue": "Root user",
                    "recommendation": "Use non-root user",
                },
            ]

            stripped = analyzer._strip_recommendations(findings)

            assert len(stripped) == 2
            for finding in stripped:
                assert "recommendation" not in finding
                assert "severity" in finding
                assert "category" in finding
                assert "issue" in finding

    def test_calculate_severity_summary(self):
        """Test severity summary calculation."""
        with patch("boto3.client"):
            analyzer = ECSSecurityAnalyzer("us-east-1")

            findings = [
                {"severity": "High"},
                {"severity": "High"},
                {"severity": "Medium"},
                {"severity": "Low"},
                {"severity": "Unknown"},  # Should be ignored
            ]

            summary = analyzer._calculate_severity_summary(findings)

            assert summary["High"] == 2
            assert summary["Medium"] == 1
            assert summary["Low"] == 1

    def test_calculate_category_summary(self):
        """Test category summary calculation."""
        with patch("boto3.client"):
            analyzer = ECSSecurityAnalyzer("us-east-1")

            findings = [
                {"category": "iam"},
                {"category": "iam"},
                {"category": "container_security"},
                {"category": "network_security"},
            ]

            summary = analyzer._calculate_category_summary(findings)

            assert summary["iam"] == 2
            assert summary["container_security"] == 1
            assert summary["network_security"] == 1

    def test_calculate_compliance_summary(self):
        """Test compliance summary calculation."""
        with patch("boto3.client"):
            analyzer = ECSSecurityAnalyzer("us-east-1")

            findings = [
                {"compliance_frameworks": ["SOC2", "HIPAA"]},
                {"compliance_frameworks": ["SOC2"]},
                {"compliance_frameworks": ["PCI-DSS"]},
                {"compliance_frameworks": []},  # Should be ignored
            ]

            summary = analyzer._calculate_compliance_summary(findings)

            assert summary["SOC2"] == 2
            assert summary["HIPAA"] == 1
            assert summary["PCI-DSS"] == 1

    @patch("boto3.client")
    def test_export_findings_to_csv(self, mock_boto_client, tmp_path):
        """Test CSV export functionality."""
        analyzer = ECSSecurityAnalyzer("us-east-1")

        findings = [
            {
                "severity": "High",
                "category": "iam",
                "resource": "Task Definition: test-task:1",
                "issue": "Missing execution role",
                "recommendation": "Add execution role",
                "compliance_frameworks": ["SOC2", "HIPAA"],
            },
            {
                "severity": "Medium",
                "category": "container_security",
                "resource": "Container: test-container",
                "issue": "Root user",
                "recommendation": "Use non-root user",
                "compliance_frameworks": ["HIPAA"],
            },
        ]

        csv_file = tmp_path / "test_findings.csv"
        result = analyzer.export_findings_to_csv(findings, str(csv_file))

        assert result is True
        assert csv_file.exists()

        # Read and verify CSV content
        content = csv_file.read_text()
        assert "severity,category,resource,issue,recommendation,compliance_frameworks" in content
        assert "High,iam" in content
        assert "Medium,container_security" in content
        assert "SOC2, HIPAA" in content

    @patch("boto3.client")
    def test_export_findings_to_csv_empty(self, mock_boto_client, tmp_path):
        """Test CSV export with empty findings."""
        analyzer = ECSSecurityAnalyzer("us-east-1")

        csv_file = tmp_path / "empty_findings.csv"
        result = analyzer.export_findings_to_csv([], str(csv_file))

        assert result is False
        assert not csv_file.exists()
