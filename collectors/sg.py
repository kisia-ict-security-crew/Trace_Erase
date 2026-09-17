import boto3
import json
from datetime import datetime, timezone
from pathlib import Path
from botocore.exceptions import ClientError

REGION = "ap-northeast-2"

ec2 = boto3.client("ec2", region_name=REGION)


def safe_call(func, default=None):
    """API 호출 실패 시 전체 프로세스가 중단되지 않도록 보호하는 예외 처리 래퍼"""
    try:
        return func()
    except ClientError as e:
        print(f"    [!] Security Group API Error: {e}")
        return default


# ============================================================
# Security Group Rule
# ============================================================

def collect_rules(rules):
    result = []

    for rule in rules:
        item = {
            "protocol": rule.get("IpProtocol"),
            "from_port": rule.get("FromPort"),
            "to_port": rule.get("ToPort"),
            "ipv4_ranges": [],
            "ipv6_ranges": [],
            "prefix_lists": [],
            "security_group_references": [],
        }

        # IPv4
        for ip_range in rule.get("IpRanges", []):
            item["ipv4_ranges"].append({
                "cidr": ip_range.get("CidrIp"),
                "description": ip_range.get("Description"),
            })

        # IPv6
        for ip_range in rule.get("Ipv6Ranges", []):
            item["ipv6_ranges"].append({
                "cidr": ip_range.get("CidrIpv6"),
                "description": ip_range.get("Description"),
            })

        # Prefix List
        for prefix in rule.get("PrefixListIds", []):
            item["prefix_lists"].append({
                "prefix_list_id": prefix.get("PrefixListId"),
                "description": prefix.get("Description"),
            })

        # 다른 Security Group 참조
        for group in rule.get("UserIdGroupPairs", []):
            item["security_group_references"].append({
                "group_id": group.get("GroupId"),
                "user_id": group.get("UserId"),
                "vpc_id": group.get("VpcId"),
                "vpc_peering_connection_id": group.get("VpcPeeringConnectionId"),
                "description": group.get("Description"),
            })

        result.append(item)

    return result


# ============================================================
# Security Group Collection
# ============================================================

def collect_security_groups():
    security_groups = []
    paginator = ec2.get_paginator("describe_security_groups")

    try:
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                security_groups.append({
                    "group_id": sg["GroupId"],
                    "group_name": sg.get("GroupName"),
                    "description": sg.get("Description"),
                    "vpc_id": sg.get("VpcId"),
                    "owner_id": sg.get("OwnerId"),
                    "ingress": collect_rules(sg.get("IpPermissions", [])),
                    "egress": collect_rules(sg.get("IpPermissionsEgress", [])),
                    "tags": {
                        tag["Key"]: tag["Value"]
                        for tag in sg.get("Tags", [])
                    },
                })
    except ClientError as e:
        print(f"    [!] Failed to describe Security Groups: {e}")

    return security_groups


# ============================================================
# Entry Point for Main Pipeline
# ============================================================

def collect_security_group():
    """snapshot.py 파이프라인에서 임포트하여 호출하는 엔트리포인트 함수"""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "resource_type": "SECURITY_GROUP",
        "resources": collect_security_groups(),
    }


# 단독 실행 시 기존 테스트 함수 호환용
def collect_snapshot():
    return collect_security_group()


if __name__ == "__main__":
    print("=" * 60)
    print("SECURITY GROUP COLLECTION (STANDALONE TEST)")
    print("=" * 60)

    snapshot = collect_security_group()
    print(f"[+] Security Groups: {len(snapshot['resources'])}")
    print("[+] Collection complete")