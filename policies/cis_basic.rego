package cloudshield.cis_basic

# CIS-Style Basic Security Checks
# Validates encryption, logging, MFA, and container security baseline

import rego.v1

# Check S3 encryption at rest
violations contains msg if {
    bucket := input.s3_buckets[_]
    not bucket.encryption.enabled
    msg := sprintf("S3 bucket '%s': encryption at rest is not enabled (CIS 2.1.1)", [bucket.name])
}

# Check S3 bucket logging
violations contains msg if {
    bucket := input.s3_buckets[_]
    not bucket.logging.enabled
    msg := sprintf("S3 bucket '%s': access logging is not enabled (CIS 2.1.2)", [bucket.name])
}

# Check CloudTrail enabled
violations contains msg if {
    not input.cloudtrail.enabled
    msg := "CloudTrail is not enabled (CIS 3.1)"
}

# Check CloudTrail multi-region
violations contains msg if {
    input.cloudtrail.enabled
    not input.cloudtrail.multi_region
    msg := "CloudTrail multi-region logging is not enabled (CIS 3.2)"
}

# Check CloudTrail log validation
violations contains msg if {
    input.cloudtrail.enabled
    not input.cloudtrail.log_file_validation
    msg := "CloudTrail log file validation is not enabled (CIS 3.3)"
}

# Check MFA on IAM roles
violations contains msg if {
    role := input.iam_roles[_]
    not role.mfa_required
    msg := sprintf("IAM role '%s': MFA is not required (CIS 1.14)", [role.name])
}

# Check privileged container
violations contains msg if {
    input.container_config.privileged
    msg := "Container runs in privileged mode (CIS Docker 5.4)"
}

# Check root user in container
violations contains msg if {
    input.container_config.run_as_root
    msg := "Container runs as root user (CIS Docker 5.7)"
}

# Check read-only root filesystem
violations contains msg if {
    not input.container_config.read_only_rootfs
    msg := "Container root filesystem is not read-only (CIS Docker 5.12)"
}

severity := "MEDIUM"
