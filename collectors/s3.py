import boto3
import json
from datetime import datetime, timezone
from pathlib import Path
from botocore.exceptions import ClientError

REGION = "ap-northeast-2"

s3 = boto3.client("s3", region_name=REGION)


# ============================================================
# Bucket Policy
# ============================================================

def collect_bucket_policy(bucket_name):
    try:
        response = s3.get_bucket_policy(Bucket=bucket_name)
        return json.loads(response["Policy"])
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code in ["NoSuchBucketPolicy", "AccessDenied"]:
            return None
        return {"error": str(e)}


# ============================================================
# ACL
# ============================================================

def collect_acl(bucket_name):
    try:
        response = s3.get_bucket_acl(Bucket=bucket_name)
        grants = []
        for grant in response.get("Grants", []):
            grantee = grant.get("Grantee", {})
            grants.append({
                "permission": grant.get("Permission"),
                "grantee": {
                    "type": grantee.get("Type"),
                    "id": grantee.get("ID"),
                    "display_name": grantee.get("DisplayName"),
                    "uri": grantee.get("URI"),
                },
            })
        return {
            "owner": response.get("Owner"),
            "grants": grants,
        }
    except Exception as e:
        return {"error": str(e)}


# ============================================================
# Public Access Block
# ============================================================

def collect_public_access_block(bucket_name):
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        return response.get("PublicAccessBlockConfiguration")
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code in ["NoSuchPublicAccessBlockConfiguration", "AccessDenied"]:
            return None
        return {"error": str(e)}


# ============================================================
# Encryption
# ============================================================

def collect_encryption(bucket_name):
    try:
        response = s3.get_bucket_encryption(Bucket=bucket_name)
        return response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code in [
            "ServerSideEncryptionConfigurationNotFoundError",
            "NoSuchBucket",
            "AccessDenied",
        ]:
            return None
        return {"error": str(e)}


# ============================================================
# Versioning
# ============================================================

def collect_versioning(bucket_name):
    try:
        response = s3.get_bucket_versioning(Bucket=bucket_name)
        return {
            "status": response.get("Status"),
            "mfa_delete": response.get("MFADelete"),
        }
    except Exception as e:
        return {"error": str(e)}


# ============================================================
# Tags
# ============================================================

def collect_tags(bucket_name):
    try:
        response = s3.get_bucket_tagging(Bucket=bucket_name)
        return {
            tag["Key"]: tag["Value"] for tag in response.get("TagSet", [])
        }
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code in ["NoSuchTagSet", "AccessDenied"]:
            return {}
        return {"error": str(e)}


# ============================================================
# Bucket Region
# ============================================================

def collect_bucket_region(bucket_name):
    try:
        response = s3.get_bucket_location(Bucket=bucket_name)
        location = response.get("LocationConstraint")

        if location is None:
            return "us-east-1"
        if location == "EU":
            return "eu-west-1"
        return location
    except Exception as e:
        return {"error": str(e)}


# ============================================================
# Bucket Collection
# ============================================================

def collect_bucket(bucket):
    bucket_name = bucket["Name"]
    creation_date = bucket.get("CreationDate")

    return {
        "bucket_name": bucket_name,
        "bucket_arn": f"arn:aws:s3:::{bucket_name}",
        "creation_date": (
            creation_date.isoformat()
            if hasattr(creation_date, "isoformat")
            else str(creation_date)
        ),
        "region": collect_bucket_region(bucket_name),
        "public_access_block": collect_public_access_block(bucket_name),
        "bucket_policy": collect_bucket_policy(bucket_name),
        "acl": collect_acl(bucket_name),
        "versioning": collect_versioning(bucket_name),
        "encryption": collect_encryption(bucket_name),
        "tags": collect_tags(bucket_name),
    }


def collect_buckets():
    buckets = []
    try:
        response = s3.list_buckets()
        for bucket in response.get("Buckets", []):
            buckets.append(collect_bucket(bucket))
    except ClientError as e:
        print(f"    [!] Failed to list S3 Buckets: {e}")
    return buckets


# ============================================================
# Entry Point for Main Pipeline
# ============================================================

def collect_s3():
    """snapshot.py 파이프라인에서 임포트하여 호출하는 엔트리포인트 함수"""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "resource_type": "S3",
        "resources": collect_buckets(),
    }


# 단독 실행 호환용
def collect_snapshot():
    return collect_s3()


if __name__ == "__main__":
    print("=" * 60)
    print("S3 RESOURCE COLLECTION (STANDALONE TEST)")
    print("=" * 60)

    snapshot = collect_s3()
    print(f"[+] S3 Buckets: {len(snapshot['resources'])}")
    print("[+] Collection complete")