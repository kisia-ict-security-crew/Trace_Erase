"""
diff.py - AWS Security Snapshot Analysis Pipeline (Fixed)
Compares JSON snapshots from 'before' and 'after' directories to detect
added, removed, and modified resources.

Fixes applied vs. the original version:
  1. IDENTIFIER_KEYS includes actual snake_case field names.
  2. Snapshot files for complex services (vpc, ec2, s3) are unwrapped.
  3. (NEW) Flattens all extracted categories back into a single 
     {"added": [], "removed": [], "modified": []} dictionary per service
     so that downstream graph builders can correctly parse the identifiers.
"""

import argparse
import json
import logging
import os
import sys
from typing import Dict, List, Any

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("diff_extractor")

SERVICE_FILES = {
    "iam": "iam.json",
    "security_group": "security_group.json",
    "ec2": "ec2.json",
    "s3": "s3.json",
    "vpc": "vpc.json",
    "cloudtrail": "cloudtrail.json"
}

# Top-level keys that are snapshot metadata, not resource categories.
METADATA_KEYS = {"timestamp", "resource_type"}

IDENTIFIER_KEYS = [
    "Arn", "TrailARN", "UserName", "RoleName", "GroupName", "PolicyArn",
    "InstanceId", "GroupId", "VpcId", "SubnetId", "Name", "BucketName", "VolumeId",
    "arn", "trail_arn", "user_name", "role_name", "group_name", "policy_arn",
    "instance_id", "group_id", "vpc_id", "subnet_id", "name", "bucket_name",
    "volume_id", "route_table_id", "internet_gateway_id", "network_acl_id",
]


def get_resource_id(item: Dict[str, Any]) -> str:
    """Extract a unique string identifier from a resource dict."""
    if not isinstance(item, dict):
        return str(item)
    for key in IDENTIFIER_KEYS:
        if key in item and item[key]:
            return str(item[key])
    return json.dumps(item, sort_keys=True)


def unwrap_categories(data: Any) -> Dict[str, List[Dict[str, Any]]]:
    """Normalize raw snapshot JSON into {category_name: [resource_dict, ...]}."""
    if data is None:
        return {}

    if isinstance(data, list):
        if not data:
            return {}
        if all(isinstance(x, dict) and any(k in x for k in IDENTIFIER_KEYS) for x in data):
            return {"_items": list(data)}
        
        merged: Dict[str, List[Dict[str, Any]]] = {}
        for wrapper in data:
            if not isinstance(wrapper, dict):
                continue
            merged.update(_categories_from_dict(wrapper))
        return merged

    if isinstance(data, dict):
        return _categories_from_dict(data)

    return {}


def _categories_from_dict(d: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    categories: Dict[str, List[Dict[str, Any]]] = {}
    found_list = False
    for k, v in d.items():
        if k in METADATA_KEYS:
            continue
        if isinstance(v, list):
            categories.setdefault(k, []).extend([x for x in v if isinstance(x, dict)])
            found_list = True
        elif isinstance(v, dict):
            categories.setdefault(k, []).append(v)
            found_list = True
    if not found_list:
        categories["_items"] = [d]
    return categories


def diff_items(before_items: List[Dict[str, Any]], after_items: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Compare two lists of same-category resource dicts by identifier."""
    before_map = {get_resource_id(item): item for item in before_items}
    after_map = {get_resource_id(item): item for item in after_items}

    before_ids = set(before_map.keys())
    after_ids = set(after_map.keys())

    added_ids = after_ids - before_ids
    removed_ids = before_ids - after_ids
    common_ids = before_ids & after_ids

    added = [after_map[rid] for rid in added_ids]
    removed = [before_map[rid] for rid in removed_ids]
    modified = []

    for rid in common_ids:
        b_item = before_map[rid]
        a_item = after_map[rid]
        if b_item != a_item:
            mod_item = dict(a_item)
            mod_item["_previous_state"] = b_item
            modified.append(mod_item)

    return {"added": added, "removed": removed, "modified": modified}


def compare_service_snapshots(before_data: Any, after_data: Any) -> Dict[str, Any]:
    """
    Compare 'before' and 'after' snapshot structures for a service.
    
    Flattens all nested categories (e.g. vpcs, subnets, route_tables) into
    a single structure: {"added": [...], "removed": [...], "modified": [...]}
    so downstream graph generators can easily parse them.
    """
    before_cats = unwrap_categories(before_data)
    after_cats = unwrap_categories(after_data)

    all_categories = set(before_cats.keys()) | set(after_cats.keys())

    # 항상 단일(Flat) 구조로 반환
    flat_result: Dict[str, List[Any]] = {"added": [], "removed": [], "modified": []}

    for cat in sorted(all_categories):
        cat_diff = diff_items(before_cats.get(cat, []), after_cats.get(cat, []))
        
        # 각 리소스에 출처 카테고리 명시 (그래프 생성기에서 참고할 수 있도록 옵션 제공)
        for item in cat_diff["added"]: item["_resource_type_category"] = cat
        for item in cat_diff["removed"]: item["_resource_type_category"] = cat
        for item in cat_diff["modified"]: item["_resource_type_category"] = cat

        flat_result["added"].extend(cat_diff["added"])
        flat_result["removed"].extend(cat_diff["removed"])
        flat_result["modified"].extend(cat_diff["modified"])

    return flat_result


def _count_changes(service_diff: Dict[str, Any]) -> int:
    """Sum added/removed/modified counts."""
    return (len(service_diff.get("added", [])) + 
            len(service_diff.get("removed", [])) + 
            len(service_diff.get("modified", [])))


class SnapshotDiffExtractor:
    """Extracts structural differences between before and after snapshot directories."""

    def __init__(self, before_dir: str = "snapshots/before", after_dir: str = "snapshots/after", output_file: str = "diff.json"):
        self.before_dir = before_dir
        self.after_dir = after_dir
        self.output_file = output_file

    def validate_directories(self):
        if not os.path.exists(self.before_dir):
            logger.error(f"Before snapshot directory '{self.before_dir}' does not exist.")
            raise FileNotFoundError(f"Directory not found: '{self.before_dir}'")
        if not os.path.exists(self.after_dir):
            logger.error(f"After snapshot directory '{self.after_dir}' does not exist.")
            raise FileNotFoundError(f"Directory not found: '{self.after_dir}'")

    def run(self) -> Dict[str, Any]:
        self.validate_directories()

        diff_result = {}
        total_changes = 0

        for service_name, file_name in SERVICE_FILES.items():
            before_path = os.path.join(self.before_dir, file_name)
            after_path = os.path.join(self.after_dir, file_name)

            before_data = None
            after_data = None

            if os.path.exists(before_path):
                try:
                    with open(before_path, "r", encoding="utf-8") as f:
                        before_data = json.load(f)
                except Exception as e:
                    logger.warning(f"Failed to read '{before_path}': {e}")

            if os.path.exists(after_path):
                try:
                    with open(after_path, "r", encoding="utf-8") as f:
                        after_data = json.load(f)
                except Exception as e:
                    logger.warning(f"Failed to read '{after_path}': {e}")

            if before_data is None and after_data is None:
                logger.info(f"Skipping service '{service_name}': Neither before nor after snapshots found.")
                continue

            service_diff = compare_service_snapshots(before_data or {}, after_data or {})
            changes_count = _count_changes(service_diff)
            total_changes += changes_count

            diff_result[service_name] = service_diff

            logger.info(
                f"Service '{service_name}': {len(service_diff['added'])} added, "
                f"{len(service_diff['removed'])} removed, {len(service_diff['modified'])} modified."
            )

        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(diff_result, f, indent=2, ensure_ascii=False)

        logger.info(f"Diff extraction complete ({total_changes} total changes detected). Output saved to '{self.output_file}'.")
        return diff_result


def main():
    parser = argparse.ArgumentParser(description="Extract diffs between AWS security snapshot directories.")
    parser.add_argument("--before", default="snapshots/before", help="Path to 'before' snapshot directory")
    parser.add_argument("--after", default="snapshots/after", help="Path to 'after' snapshot directory")
    parser.add_argument("--output", default="diff.json", help="Path to output diff.json file")

    args = parser.parse_args()

    extractor = SnapshotDiffExtractor(
        before_dir=args.before,
        after_dir=args.after,
        output_file=args.output
    )

    try:
        extractor.run()
    except Exception as e:
        logger.error(f"Diff extraction failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()