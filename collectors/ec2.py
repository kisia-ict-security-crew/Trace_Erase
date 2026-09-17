import boto3
import json
from datetime import datetime, timezone
from pathlib import Path
from botocore.exceptions import ClientError

REGION = "ap-northeast-2"

ec2 = boto3.client("ec2", region_name=REGION)


# ============================================================
# Network Interface
# ============================================================

def collect_network_interfaces(instance):
    interfaces = []
    for eni in instance.get("NetworkInterfaces", []):
        interfaces.append({
            "network_interface_id": eni.get("NetworkInterfaceId"),
            "subnet_id": eni.get("SubnetId"),
            "vpc_id": eni.get("VpcId"),
            "private_ip": eni.get("PrivateIpAddress"),
            "private_dns": eni.get("PrivateDnsName"),
            "interface_type": eni.get("InterfaceType"),
            "status": eni.get("Status"),
            "mac_address": eni.get("MacAddress"),
            "security_groups": [
                {
                    "group_id": sg.get("GroupId"),
                    "group_name": sg.get("GroupName"),
                }
                for sg in eni.get("Groups", [])
            ],
        })
    return interfaces


# ============================================================
# Block Device
# ============================================================

def collect_block_devices(instance):
    devices = []
    for device in instance.get("BlockDeviceMappings", []):
        ebs = device.get("Ebs")
        if not ebs:
            continue

        attach_time = ebs.get("AttachTime")
        devices.append({
            "device_name": device.get("DeviceName"),
            "volume_id": ebs.get("VolumeId"),
            "delete_on_termination": ebs.get("DeleteOnTermination"),
            "status": ebs.get("Status"),
            "attach_time": (
                attach_time.isoformat()
                if hasattr(attach_time, "isoformat")
                else str(attach_time) if attach_time else None
            ),
        })
    return devices


# ============================================================
# IAM Instance Profile
# ============================================================

def collect_iam_profile(instance):
    profile = instance.get("IamInstanceProfile")
    if not profile:
        return None
    return {
        "id": profile.get("Id"),
        "arn": profile.get("Arn"),
    }


# ============================================================
# EC2 Instance
# ============================================================

def collect_instance(instance):
    state = instance.get("State", {})
    placement = instance.get("Placement", {})
    launch_time = instance.get("LaunchTime")

    tags = {
        tag["Key"]: tag["Value"]
        for tag in instance.get("Tags", [])
    }

    security_groups = [
        {
            "group_id": sg.get("GroupId"),
            "group_name": sg.get("GroupName"),
        }
        for sg in instance.get("SecurityGroups", [])
    ]

    return {
        "instance_id": instance.get("InstanceId"),
        "launch_time": (
            launch_time.isoformat()
            if hasattr(launch_time, "isoformat")
            else str(launch_time) if launch_time else None
        ),
        "instance_type": instance.get("InstanceType"),
        "image_id": instance.get("ImageId"),
        "architecture": instance.get("Architecture"),
        "platform": instance.get("Platform"),
        "platform_details": instance.get("PlatformDetails"),
        "state": {
            "code": state.get("Code"),
            "name": state.get("Name"),
        },
        "availability_zone": placement.get("AvailabilityZone"),
        "tenancy": placement.get("Tenancy"),
        "subnet_id": instance.get("SubnetId"),
        "vpc_id": instance.get("VpcId"),
        "private_ip": instance.get("PrivateIpAddress"),
        "private_dns": instance.get("PrivateDnsName"),
        "public_ip": instance.get("PublicIpAddress"),
        "public_dns": instance.get("PublicDnsName"),
        "security_groups": security_groups,
        "network_interfaces": collect_network_interfaces(instance),
        "iam_instance_profile": collect_iam_profile(instance),
        "block_devices": collect_block_devices(instance),
        "monitoring": instance.get("Monitoring", {}).get("State"),
        "key_name": instance.get("KeyName"),
        "tags": tags,
    }


def collect_instances():
    instances = []
    paginator = ec2.get_paginator("describe_instances")

    try:
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instances.append(collect_instance(instance))
    except ClientError as e:
        print(f"    [!] Failed to describe EC2 Instances: {e}")

    return instances


# ============================================================
# Entry Point for Main Pipeline
# ============================================================

def collect_ec2():
    """snapshot.py 파이프라인에서 임포트하여 호출하는 엔트리포인트 함수"""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "resource_type": "EC2",
        "resources": collect_instances(),
    }


# 단독 실행 호환용
def collect_snapshot():
    return collect_ec2()


if __name__ == "__main__":
    print("=" * 60)
    print("EC2 RESOURCE COLLECTION (STANDALONE TEST)")
    print("=" * 60)

    snapshot = collect_ec2()
    print(f"[+] EC2 Instances: {len(snapshot['resources'])}")
    print("[+] Collection complete")