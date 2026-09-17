import boto3
import json
from datetime import datetime, timezone
from pathlib import Path
from botocore.exceptions import ClientError

REGION = "ap-northeast-2"

iam = boto3.client("iam", region_name=REGION)


def safe_call(func, default=None):
    """API 호출 실패 시 전체 프로세스가 중단되지 않도록 보호하는 예외 처리 래퍼"""
    try:
        return func()
    except ClientError as e:
        print(f"    [!] IAM API Error: {e}")
        return default


# ============================================================
# Managed Policy
# ============================================================

def collect_managed_policy(policy):
    policy_arn = policy["PolicyArn"]

    policy_info = safe_call(
        lambda: iam.get_policy(PolicyArn=policy_arn).get("Policy", {}),
        {}
    )
    if not policy_info:
        return {
            "policy_name": policy.get("PolicyName"),
            "policy_arn": policy_arn,
            "document": {"error": "AccessDenied or PolicyNotFound"}
        }

    default_version_id = policy_info.get("DefaultVersionId")

    try:
        version = iam.get_policy_version(
            PolicyArn=policy_arn, VersionId=default_version_id
        )
        document = version["PolicyVersion"]["Document"]
    except Exception as e:
        document = {"error": str(e)}

    return {
        "policy_name": policy.get("PolicyName"),
        "policy_arn": policy_arn,
        "policy_id": policy_info.get("PolicyId"),
        "version_id": default_version_id,
        "document": document,
    }


# ============================================================
# IAM User
# ============================================================

def collect_users():
    users = []
    paginator = iam.get_paginator("list_users")

    try:
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]

                # Managed Policies
                attached_response = safe_call(
                    lambda: iam.list_attached_user_policies(UserName=username),
                    {"AttachedPolicies": []}
                )
                attached_policies = [
                    collect_managed_policy(p) for p in attached_response.get("AttachedPolicies", [])
                ]

                # Inline Policies
                inline_response = safe_call(
                    lambda: iam.list_user_policies(UserName=username),
                    {"PolicyNames": []}
                )
                inline_policies = []
                for policy_name in inline_response.get("PolicyNames", []):
                    pol_doc = safe_call(
                        lambda: iam.get_user_policy(UserName=username, PolicyName=policy_name).get("PolicyDocument"),
                        None
                    )
                    inline_policies.append({"policy_name": policy_name, "document": pol_doc})

                # Groups
                group_response = safe_call(
                    lambda: iam.list_groups_for_user(UserName=username),
                    {"Groups": []}
                )
                groups = [
                    {"group_id": g["GroupId"], "group_name": g["GroupName"], "arn": g["Arn"]}
                    for g in group_response.get("Groups", [])
                ]

                users.append({
                    "user_id": user["UserId"],
                    "user_name": username,
                    "arn": user.get("Arn"),
                    "path": user.get("Path"),
                    "create_date": user["CreateDate"].isoformat() if hasattr(user.get("CreateDate"), "isoformat") else str(user.get("CreateDate")),
                    "attached_policies": attached_policies,
                    "inline_policies": inline_policies,
                    "groups": groups,
                })
    except ClientError as e:
        print(f"    [!] Failed to list IAM Users: {e}")

    return users


# ============================================================
# IAM Group
# ============================================================

def collect_groups():
    groups = []
    paginator = iam.get_paginator("list_groups")

    try:
        for page in paginator.paginate():
            for group in page.get("Groups", []):
                group_name = group["GroupName"]

                # Managed Policies
                attached_response = safe_call(
                    lambda: iam.list_attached_group_policies(GroupName=group_name),
                    {"AttachedPolicies": []}
                )
                attached_policies = [
                    collect_managed_policy(p) for p in attached_response.get("AttachedPolicies", [])
                ]

                # Inline Policies
                inline_response = safe_call(
                    lambda: iam.list_group_policies(GroupName=group_name),
                    {"PolicyNames": []}
                )
                inline_policies = []
                for policy_name in inline_response.get("PolicyNames", []):
                    pol_doc = safe_call(
                        lambda: iam.get_group_policy(GroupName=group_name, PolicyName=policy_name).get("PolicyDocument"),
                        None
                    )
                    inline_policies.append({"policy_name": policy_name, "document": pol_doc})

                groups.append({
                    "group_id": group["GroupId"],
                    "group_name": group_name,
                    "arn": group.get("Arn"),
                    "path": group.get("Path"),
                    "create_date": group["CreateDate"].isoformat() if hasattr(group.get("CreateDate"), "isoformat") else str(group.get("CreateDate")),
                    "attached_policies": attached_policies,
                    "inline_policies": inline_policies,
                })
    except ClientError as e:
        print(f"    [!] Failed to list IAM Groups: {e}")

    return groups


# ============================================================
# IAM Role
# ============================================================

def collect_roles():
    roles = []
    paginator = iam.get_paginator("list_roles")

    try:
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]

                # Managed Policies
                attached_response = safe_call(
                    lambda: iam.list_attached_role_policies(RoleName=role_name),
                    {"AttachedPolicies": []}
                )
                attached_policies = [
                    collect_managed_policy(p) for p in attached_response.get("AttachedPolicies", [])
                ]

                # Inline Policies
                inline_response = safe_call(
                    lambda: iam.list_role_policies(RoleName=role_name),
                    {"PolicyNames": []}
                )
                inline_policies = []
                for policy_name in inline_response.get("PolicyNames", []):
                    pol_doc = safe_call(
                        lambda: iam.get_role_policy(RoleName=role_name, PolicyName=policy_name).get("PolicyDocument"),
                        None
                    )
                    inline_policies.append({"policy_name": policy_name, "document": pol_doc})

                roles.append({
                    "role_id": role["RoleId"],
                    "role_name": role_name,
                    "arn": role.get("Arn"),
                    "path": role.get("Path"),
                    "create_date": role["CreateDate"].isoformat() if hasattr(role.get("CreateDate"), "isoformat") else str(role.get("CreateDate")),
                    "trust_policy": role.get("AssumeRolePolicyDocument"),
                    "attached_policies": attached_policies,
                    "inline_policies": inline_policies,
                })
    except ClientError as e:
        print(f"    [!] Failed to list IAM Roles: {e}")

    return roles


# ============================================================
# Entry Point for Main Pipeline
# ============================================================

def collect_iam():
    """snapshot.py 파이프라인에서 임포트하여 호출하는 엔트리포인트 함수"""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "resource_type": "IAM",
        "resources": {
            "users": collect_users(),
            "groups": collect_groups(),
            "roles": collect_roles(),
        },
    }


if __name__ == "__main__":
    print("=" * 60)
    print("IAM RESOURCE COLLECTION (STANDALONE TEST)")
    print("=" * 60)
    data = collect_iam()
    print(f"[+] Users  : {len(data['resources']['users'])}")
    print(f"[+] Groups : {len(data['resources']['groups'])}")
    print(f"[+] Roles  : {len(data['resources']['roles'])}")
    print("[+] Collection complete")