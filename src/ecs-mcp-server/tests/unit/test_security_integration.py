"""
Integration tests for the security features.
"""

import asyncio
import json
from unittest.mock import AsyncMock

import pytest

from awslabs.ecs_mcp_server.utils.security import PERMISSION_NONE, secure_tool


@pytest.fixture
def mock_config():
    """Fixture for a mock configuration."""
    return {"allow-write": True, "allow-sensitive-data": True}


class TestSecurityIntegration:
    """Integration tests for the security features."""

    def test_secure_tool_with_pii(self, mock_config):
        """Test that secure_tool properly sanitizes PII in responses."""
        # Create a mock function that returns a response with PII
        mock_func = AsyncMock(
            return_value={
                "status": "success",
                "message": "Operation completed",
                "user": {
                    "email": "user@example.com",
                    "account_id": "123456789012",
                    "ip_address": "192.168.1.1",
                },
                "aws_key": "AKIAIOSFODNN7EXAMPLE",
                "alb_url": "http://my-app-123456789.us-east-1.elb.amazonaws.com",
            }
        )

        # Apply the secure_tool decorator
        secured_func = secure_tool(mock_config, PERMISSION_NONE, "test_tool")(mock_func)

        # Call the secured function using asyncio.run
        result = asyncio.run(secured_func())

        # Check that the function was called
        mock_func.assert_called_once()

        # Check that the response was sanitized
        assert "user@example.com" not in json.dumps(result)
        assert "123456789012" not in json.dumps(result)
        assert "192.168.1.1" not in json.dumps(result)
        assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(result)

        # Check that redacted markers are present
        assert "[REDACTED EMAIL]" in json.dumps(result)
        assert "[REDACTED AWS_ACCOUNT_ID]" in json.dumps(result)
        assert "[REDACTED IP_ADDRESS]" in json.dumps(result)
        assert "[REDACTED AWS_ACCESS_KEY]" in json.dumps(result)

        # Check that warnings were added for public endpoints
        assert "warnings" in result
        assert any("publicly accessible" in warning for warning in result["warnings"])

    def test_secure_tool_with_nested_pii(self, mock_config):
        """Test that secure_tool properly sanitizes nested PII in responses."""
        # Create a mock function that returns a response with nested PII
        mock_func = AsyncMock(
            return_value={
                "status": "success",
                "message": "Operation completed",
                "resources": [
                    {
                        "name": "resource1",
                        "owner": "user@example.com",
                        "details": {
                            "account_id": "123456789012",
                            "credentials": {"password": "password=secret123"},
                        },
                    },
                    {
                        "name": "resource2",
                        "ip_addresses": ["192.168.1.1", "10.0.0.1"],
                        "aws_key": "AKIAIOSFODNN7EXAMPLE",
                    },
                ],
            }
        )

        # Apply the secure_tool decorator
        secured_func = secure_tool(mock_config, PERMISSION_NONE, "test_tool")(mock_func)

        # Call the secured function using asyncio.run
        result = asyncio.run(secured_func())

        # Check that the function was called
        mock_func.assert_called_once()

        # Convert result to JSON string for easier searching
        result_json = json.dumps(result)

        # Check that the response was sanitized
        assert "user@example.com" not in result_json
        assert "123456789012" not in result_json
        assert "password=secret123" not in result_json
        assert "192.168.1.1" not in result_json
        assert "10.0.0.1" not in result_json
        assert "AKIAIOSFODNN7EXAMPLE" not in result_json

        # Check that redacted markers are present
        assert "[REDACTED EMAIL]" in result_json
        assert "[REDACTED AWS_ACCOUNT_ID]" in result_json
        assert "[REDACTED PASSWORD]" in result_json
        assert "[REDACTED IP_ADDRESS]" in result_json
        assert "[REDACTED AWS_ACCESS_KEY]" in result_json

        # Check that non-sensitive data is preserved
        assert result["status"] == "success"
        assert result["message"] == "Operation completed"
        assert result["resources"][0]["name"] == "resource1"
        assert result["resources"][1]["name"] == "resource2"

    def test_secure_tool_with_aws_client_response(self, mock_config):
        """Test that secure_tool properly handles AWS client responses with PII."""
        # Create a mock AWS client response with PII
        aws_response = {
            "Users": [
                {
                    "UserName": "admin",
                    "UserId": "AIDACKCEVSQ6C2EXAMPLE",
                    "Email": "admin@example.com",
                    "CreateDate": "2019-12-31T12:00:00Z",
                },
                {
                    "UserName": "user",
                    "UserId": "AIDACKCEVSQ6C2EXAMPLE2",
                    "Email": "user@example.com",
                    "CreateDate": "2020-01-01T12:00:00Z",
                },
            ],
            "IsTruncated": False,
        }

        # Create a mock function that returns the AWS response
        mock_func = AsyncMock(return_value=aws_response)

        # Apply the secure_tool decorator
        secured_func = secure_tool(mock_config, PERMISSION_NONE, "test_tool")(mock_func)

        # Call the secured function using asyncio.run
        result = asyncio.run(secured_func())

        # Check that the function was called
        mock_func.assert_called_once()

        # Convert result to JSON string for easier searching
        result_json = json.dumps(result)

        # Check that the response was sanitized
        assert "admin@example.com" not in result_json
        assert "user@example.com" not in result_json

        # Check that redacted markers are present
        assert "[REDACTED EMAIL]" in result_json

        # Check that non-sensitive data is preserved
        assert result["Users"][0]["UserName"] == "admin"
        assert result["Users"][1]["UserName"] == "user"
        assert result["IsTruncated"] is False

    def test_security_analysis_pii_sanitization(self, mock_config):
        """Test that security analysis results are properly sanitized."""

        # Mock security analysis result with PII
        security_result = {
            "status": "success",
            "cluster_name": "prod-cluster",
            "findings": [
                {
                    "severity": "High",
                    "category": "iam",
                    "resource": "Task Definition: web-app:1",
                    "issue": "Missing execution role for account 123456789012",
                    "recommendation": "Add execution role arn:aws:iam::123456789012:role/execution-role",  # noqa: E501
                    "compliance_frameworks": ["SOC2"],
                },
                {
                    "severity": "Medium",
                    "category": "container_security",
                    "resource": "Container: web-container",
                    "issue": "Container exposes sensitive environment variable API_KEY=sk-1234567890abcdef",  # noqa: E501
                    "recommendation": "Use AWS Secrets Manager for API keys",
                    "compliance_frameworks": ["HIPAA"],
                },
            ],
            "detailed_results": {
                "cluster_analysis": {
                    "cluster_arn": "arn:aws:ecs:us-east-1:123456789012:cluster/prod-cluster"
                }
            },
        }

        # Create mock function that returns security analysis result
        mock_func = AsyncMock(return_value=security_result)

        # Apply the secure_tool decorator
        secured_func = secure_tool(
            mock_config, PERMISSION_NONE, "analyze_ecs_comprehensive_security"
        )(mock_func)

        # Call the secured function
        result = asyncio.run(secured_func())

        # Check that the function was called
        mock_func.assert_called_once()

        # Convert result to JSON string for easier searching
        result_json = json.dumps(result)

        # Check that PII was sanitized
        assert "123456789012" not in result_json
        # Note: API keys like sk-1234567890abcdef are not currently sanitized by the security patterns  # noqa: E501

        # Check that redacted markers are present
        assert "[REDACTED AWS_ACCOUNT_ID]" in result_json

        # Check that non-sensitive data is preserved
        assert result["status"] == "success"
        assert result["cluster_name"] == "prod-cluster"
        assert len(result["findings"]) == 2
        assert result["findings"][0]["severity"] == "High"
        assert result["findings"][1]["category"] == "container_security"

    def test_security_report_generation_sanitization(self, mock_config):
        """Test that security report generation properly sanitizes sensitive data."""
        # Mock security report with sensitive data
        security_report = {
            "cluster_name": "prod-cluster",
            "report_type": "detailed",
            "total_findings": 3,
            "findings": [
                {
                    "severity": "High",
                    "category": "secrets",
                    "resource": "Task Definition: api-service:1",
                    "issue": "Environment variable contains database password: DB_PASSWORD=mySecretPassword123",  # noqa: E501
                    "recommendation": "Use AWS Secrets Manager",
                    "compliance_frameworks": ["SOC2", "HIPAA"],
                },
                {
                    "severity": "High",
                    "category": "network_security",
                    "resource": "Security Group: sg-0123456789abcdef0",
                    "issue": "Security group allows access from IP 192.168.1.100",
                    "recommendation": "Restrict IP access",
                    "compliance_frameworks": ["PCI-DSS"],
                },
            ],
            "executive_summary": {
                "critical_issues": 2,
                "overall_assessment": "Security review for account 123456789012 completed with findings",  # noqa: E501
            },
        }

        # Create mock function that returns security report
        mock_func = AsyncMock(return_value=security_report)

        # Apply the secure_tool decorator
        secured_func = secure_tool(mock_config, PERMISSION_NONE, "generate_ecs_security_report")(
            mock_func
        )

        # Call the secured function
        result = asyncio.run(secured_func())

        # Convert result to JSON string for easier searching
        result_json = json.dumps(result)

        # Check that sensitive data was sanitized
        assert "192.168.1.100" not in result_json
        assert "123456789012" not in result_json
        # Note: Security group IDs like sg-0123456789abcdef0 are not currently sanitized by the security patterns  # noqa: E501
        # Note: Passwords in the format "DB_PASSWORD=mySecretPassword123" are sanitized by the password pattern  # noqa: E501

        # Check that redacted markers are present
        assert "[REDACTED PASSWORD]" in result_json
        assert "[REDACTED IP_ADDRESS]" in result_json
        assert "[REDACTED AWS_ACCOUNT_ID]" in result_json

        # Check that structure and non-sensitive data is preserved
        assert result["cluster_name"] == "prod-cluster"
        assert result["total_findings"] == 3
        assert result["executive_summary"]["critical_issues"] == 2

    def test_security_metrics_sanitization(self, mock_config):
        """Test that security metrics properly sanitize account information."""
        # Mock security metrics with account information
        security_metrics = {
            "cluster_name": "prod-cluster",
            "security_score": 75,
            "total_findings": 5,
            "account_info": {
                "account_id": "123456789012",
                "region": "us-east-1",
                "cluster_arn": "arn:aws:ecs:us-east-1:123456789012:cluster/prod-cluster",
            },
            "compliance_coverage": {"SOC2": 8, "HIPAA": 3, "PCI-DSS": 2},
            "risk_assessment": {
                "risk_level": "Medium",
                "high_risk_resources": [
                    "arn:aws:ecs:us-east-1:123456789012:task-definition/web-app:1",
                    "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0123456789abcdef0",
                ],
            },
        }

        # Create mock function that returns security metrics
        mock_func = AsyncMock(return_value=security_metrics)

        # Apply the secure_tool decorator
        secured_func = secure_tool(mock_config, PERMISSION_NONE, "get_ecs_security_metrics")(
            mock_func
        )

        # Call the secured function
        result = asyncio.run(secured_func())

        # Convert result to JSON string for easier searching
        result_json = json.dumps(result)

        # Check that account IDs were sanitized
        assert "123456789012" not in result_json
        # Note: Security group IDs like sg-0123456789abcdef0 are not currently sanitized by the security patterns  # noqa: E501

        # Check that redacted markers are present
        assert "[REDACTED AWS_ACCOUNT_ID]" in result_json

        # Check that metrics and structure are preserved
        assert result["cluster_name"] == "prod-cluster"
        assert result["security_score"] == 75
        assert result["total_findings"] == 5
        assert result["compliance_coverage"]["SOC2"] == 8
        assert result["risk_assessment"]["risk_level"] == "Medium"
