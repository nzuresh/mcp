#!/usr/bin/env python3
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
AWS ECS MCP Server - Main entry point
"""

import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import Any, Dict, Tuple

from fastmcp import FastMCP

from awslabs.ecs_mcp_server.modules import (
    aws_knowledge_proxy,
    containerize,
    delete,
    deployment_status,
    infrastructure,
    resource_management,
    security_analysis,
    troubleshooting,
)
from awslabs.ecs_mcp_server.utils.config import get_config
from awslabs.ecs_mcp_server.utils.security import (
    PERMISSION_WRITE,
    secure_tool,
)


def _setup_logging() -> logging.Logger:
    """Configure logging for the server."""
    log_level = os.environ.get("FASTMCP_LOG_LEVEL", "INFO")
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    log_file = os.environ.get("FASTMCP_LOG_FILE")

    logging.basicConfig(level=log_level, format=log_format)

    if log_file:
        try:
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(logging.Formatter(log_format))
            logging.getLogger().addHandler(file_handler)
            logging.info(f"Logging to file: {log_file}")
        except Exception as e:
            logging.error(f"Failed to set up log file {log_file}: {e}")

    return logging.getLogger("ecs-mcp-server")


@asynccontextmanager
async def server_lifespan(server):
    """
    Server lifespan context manager for initialization and cleanup.

    Provides safe access to async server methods during startup for
    operations like tool transformations.
    """
    logger = logging.getLogger("ecs-mcp-server")
    logger.info("Server initializing")

    # Safe async operations can be performed here
    await aws_knowledge_proxy.apply_tool_transformations(server)

    logger.info("Server ready")
    yield
    logger.info("Server shutting down")


def _create_ecs_mcp_server() -> Tuple[FastMCP, Dict[str, Any]]:
    """Create and configure the MCP server."""
    config = get_config()

    mcp = FastMCP(
        name="AWS ECS MCP Server",
        lifespan=server_lifespan,
        instructions="""Use this server to containerize, deploy, and secure applications on AWS ECS.

WORKFLOW:
1. containerize_app:
   - Get guidance on how to containerize your web application
   - Learn best practices for Dockerfile creation
   - Get recommendations for container tools and architecture

2. create_ecs_infrastructure:
   - Create the necessary AWS infrastructure for ECS deployment
   - Set up VPC, subnets, security groups, and IAM roles
   - Configure ECS Cluster, ECS Task Definitions, and ECS Services

3. get_deployment_status:
   - Check the status of your ECS deployment
   - Get the ALB URL to access your application
   - Monitor the health of your ECS Service

4. Security Analysis (NEW):
   - analyze_ecs_cluster_security: Analyze cluster security configuration
   - analyze_ecs_service_security: Analyze service security settings
   - analyze_ecs_task_definition_security: Analyze task definition security
   - analyze_ecs_comprehensive_security: Complete security analysis across all components
   - generate_ecs_security_report: Generate filtered security reports
   - get_ecs_security_metrics: Get security metrics and KPIs

SECURITY FEATURES:
- Comprehensive security analysis across all ECS components
- Support for compliance frameworks (SOC2, HIPAA, PCI-DSS)
- Detailed security findings with severity levels (High, Medium, Low)
- Actionable recommendations for security improvements
- Security metrics and scoring for monitoring
- Customizable reports with filtering options

IMPORTANT:
- Make sure your application has a clear entry point
- Ensure all dependencies are properly defined in requirements.txt, package.json, etc.
- For containerization, your application should listen on a configurable port
- AWS credentials must be properly configured with appropriate permissions
- Set ALLOW_WRITE=true to enable infrastructure creation and deletion
- Set ALLOW_SENSITIVE_DATA=true to enable access to logs and detailed resource information
- Use security analysis tools to ensure your ECS deployment follows best practices
""",
    )

    # Apply security wrappers to API functions
    # Write operations
    infrastructure.create_infrastructure = secure_tool(
        config, PERMISSION_WRITE, "create_ecs_infrastructure"
    )(infrastructure.create_infrastructure)
    delete.delete_infrastructure = secure_tool(
        config, PERMISSION_WRITE, "delete_ecs_infrastructure"
    )(delete.delete_infrastructure)

    # Register all modules
    containerize.register_module(mcp)
    infrastructure.register_module(mcp)
    deployment_status.register_module(mcp)
    resource_management.register_module(mcp)
    security_analysis.register_module(mcp)
    troubleshooting.register_module(mcp)
    delete.register_module(mcp)

    # Register all proxies
    aws_knowledge_proxy.register_proxy(mcp)

    return mcp, config


def main() -> None:
    """Main entry point for the ECS MCP Server."""
    try:
        # Start the server
        mcp, config = _create_ecs_mcp_server()
        logger = _setup_logging()

        logger.info("Server started")
        logger.info(f"Write operations enabled: {config.get('allow-write', False)}")
        logger.info(f"Sensitive data access enabled: {config.get('allow-sensitive-data', False)}")
        mcp.run()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error starting server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
