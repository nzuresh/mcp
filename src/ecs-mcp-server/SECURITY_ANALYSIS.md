# ECS Security Analysis

This document provides comprehensive information about the security analysis capabilities of the AWS ECS MCP Server.

## Overview

The ECS Security Analysis module provides comprehensive security assessment capabilities for Amazon ECS environments. It analyzes multiple layers of your ECS infrastructure to identify security vulnerabilities, misconfigurations, and compliance gaps.

## Features

### 🔍 Comprehensive Security Analysis
- **Cluster Security**: Container Insights, logging, encryption, capacity providers
- **Service Security**: Load balancer configuration, auto scaling, network settings
- **Task Definition Security**: IAM roles, container settings, secrets management
- **Container Instance Security**: ECS agent versions, instance types, security groups
- **Network Security**: VPC configuration, subnets, route tables, load balancers

### 📊 Security Reporting
- **Multiple Report Formats**: JSON, summary, detailed reports
- **Advanced Filtering**: By severity, category, compliance framework
- **Security Metrics**: Scoring, KPIs, trend analysis
- **Export Capabilities**: CSV export for external analysis

### 🛡️ Compliance Framework Support
- **SOC2**: System and Organization Controls 2
- **HIPAA**: Health Insurance Portability and Accountability Act
- **PCI-DSS**: Payment Card Industry Data Security Standard

### 📈 Security Scoring
- **Risk Assessment**: 0-100 security score with risk level classification
- **Severity Levels**: High, Medium, Low priority findings
- **Actionable Recommendations**: Detailed remediation guidance

## Available Tools

### 1. analyze_ecs_cluster_security
Analyzes the security configuration of an ECS cluster.

```python
analyze_ecs_cluster_security(
    cluster_name="my-cluster",
    region="us-east-1",
    profile="default"
)
```

**Checks Include:**
- Container Insights configuration
- Logging configuration (CloudWatch, Firelens)
- Encryption settings
- Capacity provider security
- Service discovery configuration

### 2. analyze_ecs_service_security
Analyzes the security configuration of an ECS service.

```python
analyze_ecs_service_security(
    cluster_name="my-cluster",
    service_name="my-service",
    region="us-east-1",
    profile="default"
)
```

**Checks Include:**
- Service configuration security
- Load balancer security settings
- Auto scaling configuration
- Network configuration
- Service discovery security

### 3. analyze_ecs_task_definition_security
Analyzes the security configuration of a task definition.

```python
analyze_ecs_task_definition_security(
    task_definition_arn="my-app:1",
    region="us-east-1",
    profile="default"
)
```

**Checks Include:**
- IAM role configuration (task and execution roles)
- Container security settings (privileged mode, user settings)
- Network mode security (host, bridge, awsvpc)
- Resource limits and constraints
- Environment variable security
- Secrets management
- Docker image security

### 4. analyze_ecs_comprehensive_security
Performs end-to-end security analysis across all ECS components.

```python
analyze_ecs_comprehensive_security(
    cluster_name="my-cluster",
    region="us-east-1",
    profile="default"
)
```

**Comprehensive Analysis Includes:**
- All cluster security checks
- All services in the cluster
- All task definitions used by services
- Container instances security
- Network security (VPC, subnets, security groups, load balancers)

### 5. generate_ecs_security_report
Generates customizable security reports with filtering options.

```python
generate_ecs_security_report(
    cluster_name="my-cluster",
    severity_filter=["High", "Medium"],
    category_filter=["iam", "network_security"],
    compliance_framework="SOC2",
    include_recommendations=True,
    format_type="detailed",
    region="us-east-1",
    profile="default"
)
```

**Report Types:**
- **JSON**: Raw data format for programmatic use
- **Summary**: Executive summary with key metrics
- **Detailed**: Comprehensive report with full analysis

### 6. get_ecs_security_metrics
Retrieves security metrics and KPIs for monitoring.

```python
get_ecs_security_metrics(
    cluster_name="my-cluster",
    region="us-east-1",
    profile="default"
)
```

**Metrics Include:**
- Overall security score (0-100)
- Severity distribution
- Category breakdown
- Compliance framework coverage
- Risk level assessment
- Security trends

## Security Categories

### IAM Security
- Missing task execution roles
- Missing task roles
- Overly permissive IAM policies
- Cross-account role assumptions

### Container Security
- Privileged container detection
- Root user usage
- Writable root filesystem
- Untrusted Docker images
- Missing security contexts

### Network Security
- Host network mode usage
- Insecure network configurations
- Missing security groups
- Load balancer security
- VPC and subnet security

### Secrets Management
- Hardcoded secrets in environment variables
- Missing secrets management
- Insecure secret storage
- Environment variable exposure

### Resource Management
- Missing CPU/memory limits
- Resource constraint violations
- Capacity planning issues
- Performance security implications

### Monitoring & Logging
- Missing health checks
- Insufficient logging configuration
- Missing monitoring setup
- Audit trail gaps

## Severity Levels

### High Severity
- **Impact**: Critical security vulnerabilities
- **Examples**: Missing IAM roles, privileged containers, exposed secrets
- **Action**: Immediate remediation required
- **Score Impact**: -20 points per finding

### Medium Severity
- **Impact**: Significant security concerns
- **Examples**: Root user usage, missing resource limits, weak configurations
- **Action**: Remediate within 2-8 weeks
- **Score Impact**: -10 points per finding

### Low Severity
- **Impact**: Minor security improvements
- **Examples**: Missing health checks, optimization opportunities
- **Action**: Address in next maintenance cycle
- **Score Impact**: -5 points per finding

## Compliance Framework Mapping

### SOC2 (System and Organization Controls 2)
- Access controls and authentication
- System monitoring and logging
- Data protection and encryption
- Change management processes

### HIPAA (Health Insurance Portability and Accountability Act)
- Data encryption requirements
- Access controls for PHI
- Audit logging and monitoring
- Administrative safeguards

### PCI-DSS (Payment Card Industry Data Security Standard)
- Network security requirements
- Access control measures
- Encryption of cardholder data
- Security monitoring and testing

## Best Practices

### 1. Regular Security Assessments
- Run comprehensive security analysis monthly
- Monitor security metrics continuously
- Address High severity findings immediately
- Track security improvements over time

### 2. Compliance Monitoring
- Filter reports by relevant compliance frameworks
- Document remediation efforts
- Maintain audit trails
- Regular compliance reviews

### 3. Security Automation
- Integrate security analysis into CI/CD pipelines
- Set up automated alerts for High severity findings
- Use security metrics for dashboard monitoring
- Implement security gates in deployment processes

### 4. Team Collaboration
- Share security reports with development teams
- Provide training on security best practices
- Establish security review processes
- Create security champions program

## Example Usage Scenarios

### Scenario 1: Initial Security Assessment
```python
# Perform comprehensive analysis
result = analyze_ecs_comprehensive_security("production-cluster")

# Generate executive summary
report = generate_ecs_security_report(
    cluster_name="production-cluster",
    format_type="summary"
)

# Get security metrics for dashboard
metrics = get_ecs_security_metrics("production-cluster")
```

### Scenario 2: Compliance Audit
```python
# Generate SOC2 compliance report
soc2_report = generate_ecs_security_report(
    cluster_name="production-cluster",
    compliance_framework="SOC2",
    format_type="detailed",
    include_recommendations=True
)

# Filter for High severity compliance issues
critical_issues = generate_ecs_security_report(
    cluster_name="production-cluster",
    severity_filter=["High"],
    compliance_framework="SOC2"
)
```

### Scenario 3: Continuous Monitoring
```python
# Get current security metrics
current_metrics = get_ecs_security_metrics("production-cluster")

# Monitor specific categories
network_issues = generate_ecs_security_report(
    cluster_name="production-cluster",
    category_filter=["network_security"],
    severity_filter=["High", "Medium"]
)
```

### Scenario 4: Task Definition Review
```python
# Analyze specific task definition
td_analysis = analyze_ecs_task_definition_security("my-app:latest")

# Focus on IAM and container security
security_report = generate_ecs_security_report(
    cluster_name="production-cluster",
    category_filter=["iam", "container_security"],
    include_recommendations=True
)
```

## Integration Examples

### CI/CD Pipeline Integration
```yaml
# Example GitHub Actions workflow
- name: ECS Security Analysis
  run: |
    # Run security analysis
    python -c "
    from ecs_mcp_server.modules.security_analysis import analyze_ecs_comprehensive_security
    result = analyze_ecs_comprehensive_security('${{ env.CLUSTER_NAME }}')
    
    # Fail if High severity findings
    high_severity = len([f for f in result['findings'] if f['severity'] == 'High'])
    if high_severity > 0:
        print(f'Found {high_severity} High severity security issues')
        exit(1)
    "
```

### Monitoring Dashboard Integration
```python
# Example monitoring script
import json
from ecs_mcp_server.modules.security_analysis import get_ecs_security_metrics

def update_security_dashboard():
    clusters = ["prod-cluster", "staging-cluster", "dev-cluster"]
    
    for cluster in clusters:
        metrics = get_ecs_security_metrics(cluster)
        
        # Send to monitoring system
        send_metrics_to_dashboard({
            "cluster": cluster,
            "security_score": metrics["security_score"],
            "risk_level": metrics["risk_level"],
            "high_severity_count": metrics["severity_distribution"]["High"]
        })
```

## Troubleshooting

### Common Issues

1. **Permission Errors**
   - Ensure AWS credentials have necessary ECS, EC2, and VPC permissions
   - Check IAM policies for read access to all analyzed resources

2. **Resource Not Found**
   - Verify cluster names and resource identifiers
   - Ensure resources exist in the specified region

3. **Analysis Timeouts**
   - Large clusters may take longer to analyze
   - Consider using service-specific analysis for faster results

4. **Missing Findings**
   - Some checks require specific AWS service configurations
   - Review the analysis logs for any skipped checks

### Debug Mode
Enable debug logging for detailed analysis information:
```python
import logging
logging.getLogger("ecs_mcp_server").setLevel(logging.DEBUG)
```

## Contributing

To extend the security analysis capabilities:

1. Add new security checks to the `ECSSecurityAnalyzer` class
2. Update the severity and category mappings
3. Add compliance framework mappings as needed
4. Update documentation and examples

## Support

For issues, questions, or feature requests related to security analysis:
- Review the analysis logs for detailed error information
- Check AWS permissions and resource accessibility
- Verify the latest version of the ECS MCP Server
- Submit issues with detailed reproduction steps