"""
diff.py - AWS Security Snapshot Analysis Pipeline (Refactored)
Compares JSON snapshots from 'before' and 'after' directories to detect added, removed, and modified resources.
Outputs structured diff.json for normalize_diff.py.
"""

import argparse
import json
import logging
import os
import sys
from typing import Dict, List, Any, Optional, Union

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("diff_extractor")

# Default service snapshot files
SERVICE_FILES = {
    "iam": "iam.json",
    "security_group": "security_group.json",
    "ec2": "ec2.json",
    "s3": "s3.json",
    "vpc": "vpc.json",
    "cloudtrail": "cloudtrail.json"
}

# Unique identification keys for resource matching
IDENTIFIER_KEYS = [
    "Arn", "TrailARN", "UserName", "RoleName", "GroupName", "PolicyArn",
    "InstanceId", "GroupId", "VpcId", "SubnetId", "Name", "BucketName", "VolumeId"
]


def get_resource_id(item: Dict[str, Any]) -> str:
    """Extract a unique string identifier from a resource dict."""
    if not isinstance(item, dict):
        return str(item)
    for key in IDENTIFIER_KEYS:
        if key in item and item[key]:
            return str(item[key])
    return json.dumps(item, sort_keys=True)


def extract_items_list(data: Any) -> List[Dict[str, Any]]:
    """Normalize raw JSON data into a flat list of dict items."""
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    elif isinstance(data, dict):
        items = []
        for k, v in data.items():
            if isinstance(v, list):
                items.extend([x for x in v if isinstance(x, dict)])
            elif isinstance(v, dict):
                items.append(v)
        return items if items else [data]
    return []


def compare_service_snapshots(before_data: Any, after_data: Any) -> Dict[str, List[Dict[str, Any]]]:
    """Compare 'before' and 'after' snapshot structures for a service."""
    before_list = extract_items_list(before_data)
    after_list = extract_items_list(after_data)

    before_map = {get_resource_id(item): item for item in before_list}
    after_map = {get_resource_id(item): item for item in after_list}

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

        # Check for deep structural inequality
        if b_item != a_item:
            # Store 'after' state with previous context if modified
            mod_item = dict(a_item)
            mod_item["_previous_state"] = b_item
            modified.append(mod_item)

    return {
        "added": added,
        "removed": removed,
        "modified": modified
    }


class SnapshotDiffExtractor:
    """Extracts structural differences between before and after snapshot directories."""

    def __init__(self, before_dir: str = "snapshots/before", after_dir: str = "snapshots/after", output_file: str = "diff.json"):
        self.before_dir = before_dir
        self.after_dir = after_dir
        self.output_file = output_file

    def validate_directories(self):
        """Validate existence of before and after snapshot directories."""
        if not os.path.exists(self.before_dir):
            logger.error(f"Before snapshot directory '{self.before_dir}' does not exist.")
            raise FileNotFoundError(f"Directory not found: '{self.before_dir}'")

        if not os.path.exists(self.after_dir):
            logger.error(f"After snapshot directory '{self.after_dir}' does not exist.")
            raise FileNotFoundError(f"Directory not found: '{self.after_dir}'")

    def run(self) -> Dict[str, Any]:
        """Execute diff comparison across all service snapshot files."""
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
            
            changes_count = (
                len(service_diff["added"]) +
                len(service_diff["removed"]) +
                len(service_diff["modified"])
            )
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
