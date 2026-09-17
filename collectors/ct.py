import boto3
import json
from datetime import datetime, timezone
from pathlib import Path
from botocore.exceptions import ClientError

REGION = "ap-northeast-2"

OUTPUT_DIR = Path("snapshots")
OUTPUT_DIR.mkdir(exist_ok=True)

cloudtrail = boto3.client("cloudtrail", region_name=REGION)


# ============================================================
# Event Selectors
# ============================================================

def collect_event_selectors(trail_name):
    try:
        response = cloudtrail.get_event_selectors(TrailName=trail_name)
        return {
            "event_selectors": response.get("EventSelectors", []),
            "advanced_event_selectors": response.get("AdvancedEventSelectors", []),
        }
    except ClientError as e:
        return {"error": str(e)}


# ============================================================
# Insight Selectors
# ============================================================

def collect_insight_selectors(trail_name):
    try:
        response = cloudtrail.get_insight_selectors(TrailName=trail_name)
        return response.get("InsightSelectors", [])
    except ClientError:
        return []


# ============================================================
# Trail Status
# ============================================================

def collect_trail_status(trail_name):
    try:
        status = cloudtrail.get_trail_status(Name=trail_name)
        return {
            "is_logging": status.get("IsLogging", False),
            "latest_delivery_time": (
                status["LatestDeliveryTime"].isoformat()
                if hasattr(status.get("LatestDeliveryTime"), "isoformat")
                else str(status.get("LatestDeliveryTime")) if status.get("LatestDeliveryTime") else None
            ),
            "latest_notification_time": (
                status["LatestNotificationTime"].isoformat()
                if hasattr(status.get("LatestNotificationTime"), "isoformat")
                else str(status.get("LatestNotificationTime")) if status.get("LatestNotificationTime") else None
            ),
            "latest_cloudwatch_logs_delivery_time": (
                status["LatestCloudWatchLogsDeliveryTime"].isoformat()
                if hasattr(status.get("LatestCloudWatchLogsDeliveryTime"), "isoformat")
                else str(status.get("LatestCloudWatchLogsDeliveryTime")) if status.get("LatestCloudWatchLogsDeliveryTime") else None
            ),
            "latest_cloudwatch_logs_delivery_error": status.get("LatestCloudWatchLogsDeliveryError"),
            "latest_delivery_error": status.get("LatestDeliveryError"),
            "latest_digest_delivery_time": (
                status["LatestDigestDeliveryTime"].isoformat()
                if hasattr(status.get("LatestDigestDeliveryTime"), "isoformat")
                else str(status.get("LatestDigestDeliveryTime")) if status.get("LatestDigestDeliveryTime") else None
            ),
            "latest_digest_delivery_error": status.get("LatestDigestDeliveryError"),
        }
    except ClientError as e:
        return {"is_logging": None, "error": str(e)}


# ============================================================
# Trail Collection
# ============================================================

def collect_trails():
    trails = []
    try:
        response = cloudtrail.describe_trails(includeShadowTrails=True)
        for trail in response.get("trailList", []):
            trail_name = trail.get("Name")
            trail_arn = trail.get("TrailARN")

            status = collect_trail_status(trail_arn or trail_name)
            selectors = collect_event_selectors(trail_arn or trail_name)
            insights = collect_insight_selectors(trail_arn or trail_name)

            trails.append({
                "trail_arn": trail_arn,
                "name": trail_name,
                "home_region": trail.get("HomeRegion"),
                "s3_bucket_name": trail.get("S3BucketName"),
                "s3_key_prefix": trail.get("S3KeyPrefix"),
                "include_global_service_events": trail.get("IncludeGlobalServiceEvents"),
                "is_multi_region_trail": trail.get("IsMultiRegionTrail"),
                "is_organization_trail": trail.get("IsOrganizationTrail"),
                "log_file_validation_enabled": trail.get("LogFileValidationEnabled"),
                "kms_key_id": trail.get("KMSKeyId"),
                "cloudwatch_logs_log_group_arn": trail.get("CloudWatchLogsLogGroupArn"),
                "cloudwatch_logs_role_arn": trail.get("CloudWatchLogsRoleArn"),
                "sns_topic_arn": trail.get("SnsTopicARN"),
                "has_custom_event_selectors": trail.get("HasCustomEventSelectors"),
                "has_insight_selectors": trail.get("HasInsightSelectors"),
                "event_selectors": selectors,
                "insight_selectors": insights,
                "status": status,
            })
    except ClientError as e:
        print(f"[!] CloudTrail collection error: {e}")

    return trails


# ============================================================
# Entry Point for Main Pipeline
# ============================================================

def collect_cloudtrail():
    """snapshot.py 파이프라인에서 임포트하여 호출하는 엔트리포인트 함수"""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "resource_type": "CLOUDTRAIL",
        "resources": collect_trails(),
    }


# 단독 실행 호환용
def collect_snapshot():
    return collect_cloudtrail()


if __name__ == "__main__":
    print("=" * 60)
    print("CLOUDTRAIL RESOURCE COLLECTION (STANDALONE TEST)")
    print("=" * 60)

    snapshot = collect_cloudtrail()
    trails = snapshot["resources"]
    print(f"[+] Trails: {len(trails)}")

    for trail in trails:
        status = trail.get("status", {})
        print(f"    - {trail.get('name')}")
        print(f"      ARN: {trail.get('trail_arn')}")
        print(f"      Logging: {status.get('is_logging')}")

    print("[+] Collection complete")