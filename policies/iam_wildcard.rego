package cloudshield.iam_wildcard

# IAM Wildcard Permissions Check
# Detects IAM roles/policies with overly permissive wildcard actions or resources

import rego.v1

violations contains msg if {
    role := input.iam_roles[_]
    policy := role.policies[_]
    policy.action == "*"
    msg := sprintf("IAM role '%s' policy '%s' grants wildcard Action '*'", [role.name, policy.name])
}

violations contains msg if {
    role := input.iam_roles[_]
    policy := role.policies[_]
    policy.resource == "*"
    msg := sprintf("IAM role '%s' policy '%s' grants access to all Resources '*'", [role.name, policy.name])
}

violations contains msg if {
    role := input.iam_roles[_]
    policy := role.policies[_]
    endswith(policy.action, ":*")
    msg := sprintf("IAM role '%s' policy '%s' grants wildcard service action '%s'", [role.name, policy.name, policy.action])
}

severity := "CRITICAL"
