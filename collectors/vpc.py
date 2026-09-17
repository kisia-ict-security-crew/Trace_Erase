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
        print(f"    [!] VPC API Error: {e}")
        return default


# ============================================================
# VPC
# ============================================================

def collect_vpcs():
    vpcs = []
    paginator = ec2.get_paginator("describe_vpcs")

    try:
        for page in paginator.paginate():
            for vpc in page.get("Vpcs", []):
                vpcs.append({
                    "vpc_id": vpc["VpcId"],
                    "cidr_block": vpc.get("CidrBlock"),
                    "state": vpc.get("State"),
                    "is_default": vpc.get("IsDefault"),
                    "dhcp_options_id": vpc.get("DhcpOptionsId"),
                    "tags": {
                        tag["Key"]: tag["Value"]
                        for tag in vpc.get("Tags", [])
                    },
                })
    except ClientError as e:
        print(f"    [!] Failed to describe VPCs: {e}")

    return vpcs


# ============================================================
# Subnet
# ============================================================

def collect_subnets():
    subnets = []
    paginator = ec2.get_paginator("describe_subnets")

    try:
        for page in paginator.paginate():
            for subnet in page.get("Subnets", []):
                subnets.append({
                    "subnet_id": subnet["SubnetId"],
                    "vpc_id": subnet.get("VpcId"),
                    "cidr_block": subnet.get("CidrBlock"),
                    "availability_zone": subnet.get("AvailabilityZone"),
                    "availability_zone_id": subnet.get("AvailabilityZoneId"),
                    "state": subnet.get("State"),
                    "map_public_ip_on_launch": subnet.get("MapPublicIpOnLaunch"),
                    "available_ip_count": subnet.get("AvailableIpAddressCount"),
                    "default_for_az": subnet.get("DefaultForAz"),
                    "tags": {
                        tag["Key"]: tag["Value"]
                        for tag in subnet.get("Tags", [])
                    },
                })
    except ClientError as e:
        print(f"    [!] Failed to describe Subnets: {e}")

    return subnets


# ============================================================
# Route Table
# ============================================================

def collect_route_tables():
    route_tables = []
    paginator = ec2.get_paginator("describe_route_tables")

    try:
        for page in paginator.paginate():
            for table in page.get("RouteTables", []):
                routes = [
                    {
                        "destination_cidr": route.get("DestinationCidrBlock"),
                        "destination_ipv6": route.get("DestinationIpv6CidrBlock"),
                        "destination_prefix_list": route.get("DestinationPrefixListId"),
                        "gateway_id": route.get("GatewayId"),
                        "nat_gateway_id": route.get("NatGatewayId"),
                        "network_interface_id": route.get("NetworkInterfaceId"),
                        "transit_gateway_id": route.get("TransitGatewayId"),
                        "instance_id": route.get("InstanceId"),
                        "state": route.get("State"),
                        "origin": route.get("Origin"),
                    }
                    for route in table.get("Routes", [])
                ]

                associations = [
                    {
                        "route_table_association_id": assoc.get("RouteTableAssociationId"),
                        "subnet_id": assoc.get("SubnetId"),
                        "main": assoc.get("Main"),
                        "association_state": assoc.get("AssociationState"),
                    }
                    for assoc in table.get("Associations", [])
                ]

                route_tables.append({
                    "route_table_id": table["RouteTableId"],
                    "vpc_id": table.get("VpcId"),
                    "routes": routes,
                    "associations": associations,
                    "tags": {
                        tag["Key"]: tag["Value"]
                        for tag in table.get("Tags", [])
                    },
                })
    except ClientError as e:
        print(f"    [!] Failed to describe Route Tables: {e}")

    return route_tables


# ============================================================
# Internet Gateway
# ============================================================

def collect_internet_gateways():
    gateways = []
    paginator = ec2.get_paginator("describe_internet_gateways")

    try:
        for page in paginator.paginate():
            for gateway in page.get("InternetGateways", []):
                attachments = [
                    {
                        "vpc_id": att.get("VpcId"),
                        "state": att.get("State"),
                    }
                    for att in gateway.get("Attachments", [])
                ]

                gateways.append({
                    "internet_gateway_id": gateway["InternetGatewayId"],
                    "attachments": attachments,
                    "tags": {
                        tag["Key"]: tag["Value"]
                        for tag in gateway.get("Tags", [])
                    },
                })
    except ClientError as e:
        print(f"    [!] Failed to describe Internet Gateways: {e}")

    return gateways


# ============================================================
# Network ACL
# ============================================================

def collect_network_acls():
    acls = []
    paginator = ec2.get_paginator("describe_network_acls")

    try:
        for page in paginator.paginate():
            for acl in page.get("NetworkAcls", []):
                entries = [
                    {
                        "rule_number": entry.get("RuleNumber"),
                        "protocol": entry.get("Protocol"),
                        "rule_action": entry.get("RuleAction"),
                        "egress": entry.get("Egress"),
                        "cidr_block": entry.get("CidrBlock"),
                        "ipv6_cidr_block": entry.get("Ipv6CidrBlock"),
                        "icmp_type_code": entry.get("IcmpTypeCode"),
                        "port_range": entry.get("PortRange"),
                    }
                    for entry in acl.get("Entries", [])
                ]

                associations = [
                    {
                        "association_id": assoc.get("NetworkAclAssociationId"),
                        "subnet_id": assoc.get("SubnetId"),
                    }
                    for assoc in acl.get("Associations", [])
                ]

                acls.append({
                    "network_acl_id": acl["NetworkAclId"],
                    "vpc_id": acl.get("VpcId"),
                    "is_default": acl.get("IsDefault"),
                    "entries": entries,
                    "associations": associations,
                    "tags": {
                        tag["Key"]: tag["Value"]
                        for tag in acl.get("Tags", [])
                    },
                })
    except ClientError as e:
        print(f"    [!] Failed to describe Network ACLs: {e}")

    return acls


# ============================================================
# Entry Point for Main Pipeline
# ============================================================

def collect_vpc():
    """snapshot.py 파이프라인에서 임포트하여 호출하는 엔트리포인트 함수"""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "resource_type": "VPC",
        "resources": {
            "vpcs": collect_vpcs(),
            "subnets": collect_subnets(),
            "route_tables": collect_route_tables(),
            "internet_gateways": collect_internet_gateways(),
            "network_acls": collect_network_acls(),
        },
    }


# 단독 실행 호환용
def collect_snapshot():
    return collect_vpc()


if __name__ == "__main__":
    print("=" * 60)
    print("VPC RESOURCE COLLECTION (STANDALONE TEST)")
    print("=" * 60)

    snapshot = collect_vpc()
    res = snapshot["resources"]

    print(f"[+] VPCs: {len(res['vpcs'])}")
    print(f"[+] Subnets: {len(res['subnets'])}")
    print(f"[+] Route Tables: {len(res['route_tables'])}")
    print(f"[+] Internet Gateways: {len(res['internet_gateways'])}")
    print(f"[+] Network ACLs: {len(res['network_acls'])}")
    print("[+] Collection complete")