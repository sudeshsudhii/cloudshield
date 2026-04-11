package cloudshield.s3_public

# S3 Public Access Check
# Detects S3 buckets with public access enabled or public access block not configured

import rego.v1

violations contains msg if {
    bucket := input.s3_buckets[_]
    bucket.acl == "public-read"
    msg := sprintf("S3 bucket '%s' has public-read ACL", [bucket.name])
}

violations contains msg if {
    bucket := input.s3_buckets[_]
    bucket.acl == "public-read-write"
    msg := sprintf("S3 bucket '%s' has public-read-write ACL", [bucket.name])
}

violations contains msg if {
    bucket := input.s3_buckets[_]
    not bucket.public_access_block.block_public_acls
    msg := sprintf("S3 bucket '%s': BlockPublicAcls is not enabled", [bucket.name])
}

violations contains msg if {
    bucket := input.s3_buckets[_]
    not bucket.public_access_block.block_public_policy
    msg := sprintf("S3 bucket '%s': BlockPublicPolicy is not enabled", [bucket.name])
}

severity := "HIGH"
