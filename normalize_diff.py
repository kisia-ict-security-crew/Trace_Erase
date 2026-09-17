"""
normalize_diff-v4.py - AWS Security Snapshot Analysis Pipeline (Refactored v4)
Normalizes raw diff.json into standardized Node and Relationship graph schemas for Neo4j.
Eliminates dummy/ghost 'Unknown' nodes by strictly validating resource type keys.
"""

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
logger = logging.getLogger("normalize_diff")


class SchemaNormalizer:
    """Normalizes raw diff data into a uniform Graph Schema (Nodes and Relationships)."""

    def __init__(self, account_id: str = "123456789012", region: str = "ap-northeast-2"):
        self.account_id = account_id
        self.region = region
        self.nodes: List[Dict[str, Any]] = []
        self.relationships: List[Dict[str, Any]] = []

    def sanitize_properties(self, props: Dict[str, Any]) -> Dict[str, Any]:
        """Convert nested dicts/lists into Neo4j primitive-compatible formats."""
        sanitized = {}
        for key, val in props.items():
            if val is None:
                continue
            if isinstance(val, (str, int, float, bool)):
                sanitized[key] = val
            elif isinstance(val, (dict, list)):
                sanitized[key] = json.dumps(val, ensure_ascii=False, default=str)
            else:
                sanitized[key] = str(val)
        return sanitized

    def format_arn(self, service: str, resource_type: str, resource_id: str) -> str:
        """Generate deterministic ARN / Unique Identifier for resources."""
        if str(resource_id).startswith("arn:aws:"):
            return str(resource_id)
        if service == "s3":
            return f"arn:aws:s3:::{resource_id}"
        if service == "iam":
            return f"arn:aws:iam::{self.account_id}:{resource_type}/{resource_id}"
        return f"arn:aws:{service}:{self.region}:{self.account_id}:{resource_type}/{resource_id}"

    def add_node(self, node_id: str, labels: List[str], change_type: str, props: Dict[str, Any]):
        """Register a normalized node with deduplication and validation."""
        if not node_id or "Unknown" in node_id or "sg-unknown" in node_id:
            logger.debug(f"Skipping invalid/dummy node ID: {node_id}")
            return

        for existing in self.nodes:
            if existing["id"] == node_id and existing["change_type"] == change_type:
                existing["properties"].update(self.sanitize_properties(props))
                return

        self.nodes.append({
            "id": node_id,
            "labels": labels,
            "change_type": change_type,  # 'ADDED', 'REMOVED', 'MODIFIED'
            "properties": self.sanitize_properties(props)
        })

    def add_relationship(self, source_id: str, target_id: str, rel_type: str, change_type: str, props: Optional[Dict[str, Any]] = None):
        """Register a normalized relationship."""
        if not source_id or not target_id or "Unknown" in source_id or "Unknown" in target_id:
            return

        rel_entry = {
            "source": source_id,
            "target": target_id,
            "type": rel_type,
            "change_type": change_type,
            "properties": self.sanitize_properties(props or {})
        }
        if rel_entry not in self.relationships:
            self.relationships.append(rel_entry)

    @staticmethod
    def _filter_items(data: Any, required_keys: Union[str, List[str]]) -> List[Dict[str, Any]]:
        """Strictly filter and extract items containing specific resource identifying keys."""
        keys = [required_keys] if isinstance(required_keys, str) else required_keys
        
        def has_valid_key(item: Dict[str, Any]) -> bool:
            for k in keys:
                val = str(item.get(k, "")).strip()
                if val and val not in ("Unknown", "sg-unknown", "default_value"):
                    return True
            return False

        extracted = []
        if isinstance(data, list):
            for x in data:
                if isinstance(x, dict) and has_valid_key(x):
                    extracted.append(x)
        elif isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, list):
                    extracted.extend([x for x in v if isinstance(x, dict) and has_valid_key(x)])
                elif isinstance(v, dict) and has_valid_key(v):
                    extracted.append(v)
            if not extracted and has_valid_key(data):
                extracted.append(data)

        return extracted

    # --- Service Specific Normalizers ---

    def normalize_iam(self, iam_diff: Dict[str, Any]):
        """Normalize IAM Users, Groups, Roles, Policies strictly filtering by key presence."""
        for change_type in ["added", "removed", "modified"]:
            raw_data = iam_diff.get(change_type, {})
            action = change_type.upper()

            # 1. Process Users
            users = self._filter_items(raw_data, "UserName")
            for user in users:
                user_name = user["UserName"]
                user_arn = user.get("Arn") or self.format_arn("iam", "user", user_name)
                
                self.add_node(
                    node_id=user_arn,
                    labels=["Resource", "IAM", "IAMUser"],
                    change_type=action,
                    props={"UserName": user_name, "UserId": user.get("UserId", "")}
                )

                for pol in user.get("AttachedPolicies", []):
                    pol_arn = pol.get("PolicyArn") if isinstance(pol, dict) else str(pol)
                    pol_name = pol.get("PolicyName") if isinstance(pol, dict) else pol_arn.split('/')[-1]
                    if pol_arn and "Unknown" not in pol_arn:
                        self.add_node(
                            node_id=pol_arn,
                            labels=["Resource", "IAM", "IAMPolicy"],
                            change_type=action,
                            props={"PolicyArn": pol_arn, "PolicyName": pol_name}
                        )
                        self.add_relationship(user_arn, pol_arn, "HAS_POLICY", action)

            # 2. Process Roles
            roles = self._filter_items(raw_data, "RoleName")
            for role in roles:
                role_name = role["RoleName"]
                role_arn = role.get("Arn") or self.format_arn("iam", "role", role_name)
                
                self.add_node(
                    node_id=role_arn,
                    labels=["Resource", "IAM", "IAMRole"],
                    change_type=action,
                    props={"RoleName": role_name, "RoleId": role.get("RoleId", "")}
                )

                for pol in role.get("AttachedPolicies", []):
                    pol_arn = pol.get("PolicyArn") if isinstance(pol, dict) else str(pol)
                    pol_name = pol.get("PolicyName") if isinstance(pol, dict) else pol_arn.split('/')[-1]
                    if pol_arn and "Unknown" not in pol_arn:
                        self.add_node(
                            node_id=pol_arn,
                            labels=["Resource", "IAM", "IAMPolicy"],
                            change_type=action,
                            props={"PolicyArn": pol_arn, "PolicyName": pol_name}
                        )
                        self.add_relationship(role_arn, pol_arn, "HAS_POLICY", action)

            # 3. Process Groups
            groups = self._filter_items(raw_data, "GroupName")
            for group in groups:
                group_name = group["GroupName"]
                group_arn = group.get("Arn") or self.format_arn("iam", "group", group_name)

                self.add_node(
                    node_id=group_arn,
                    labels=["Resource", "IAM", "IAMGroup"],
                    change_type=action,
                    props={"GroupName": group_name, "GroupId": group.get("GroupId", "")}
                )

    def normalize_s3(self, s3_diff: Dict[str, Any]):
        """Normalize S3 Bucket configurations strictly checking bucket name keys."""
        for change_type in ["added", "removed", "modified"]:
            raw_data = s3_diff.get(change_type, {})
            action = change_type.upper()

            buckets = self._filter_items(raw_data, ["Name", "BucketName"])
            for bucket in buckets:
                b_name = bucket.get("Name") or bucket.get("BucketName")
                if not b_name or b_name == "Unknown":
                    continue
                b_arn = self.format_arn("s3", "bucket", b_name)

                props = {
                    "BucketName": b_name,
                    "PublicAccessBlock": bucket.get("PublicAccessBlock", {}),
                    "Encryption": bucket.get("Encryption", {})
                }
                
                self.add_node(
                    node_id=b_arn,
                    labels=["Resource", "S3", "S3Bucket"],
                    change_type=action,
                    props=props
                )

    def normalize_security_groups(self, sg_diff: Dict[str, Any]):
        """Normalize Security Groups and Network Rules strictly validating GroupId."""
        for change_type in ["added", "removed", "modified"]:
            raw_data = sg_diff.get(change_type, {})
            action = change_type.upper()

            sgs = self._filter_items(raw_data, "GroupId")
            for sg in sgs:
                sg_id = sg["GroupId"]
                if not sg_id or sg_id == "sg-unknown":
                    continue
                sg_arn = self.format_arn("ec2", "security-group", sg_id)

                self.add_node(
                    node_id=sg_arn,
                    labels=["Resource", "EC2", "SecurityGroup"],
                    change_type=action,
                    props={
                        "GroupId": sg_id,
                        "GroupName": sg.get("GroupName", ""),
                        "VpcId": sg.get("VpcId", "")
                    }
                )

                if sg.get("VpcId") and sg.get("VpcId") != "Unknown":
                    vpc_id = sg.get("VpcId")
                    vpc_arn = self.format_arn("ec2", "vpc", vpc_id)
                    self.add_node(
                        node_id=vpc_arn,
                        labels=["Resource", "EC2", "VPC"],
                        change_type=action,
                        props={"VpcId": vpc_id}
                    )
                    self.add_relationship(sg_arn, vpc_arn, "BELONGS_TO_VPC", action)

    def normalize_cloudtrail(self, ct_diff: Dict[str, Any]):
        """Normalize CloudTrail trails & logging status strictly checking Trail Name / ARN."""
        for change_type in ["added", "removed", "modified"]:
            raw_data = ct_diff.get(change_type, {})
            action = change_type.upper()

            trails = self._filter_items(raw_data, ["Name", "TrailARN"])
            for trail in trails:
                t_name = trail.get("Name") or (trail.get("TrailARN", "").split("/")[-1] if trail.get("TrailARN") else None)
                if not t_name or t_name == "Unknown":
                    continue

                t_arn = trail.get("TrailARN") or self.format_arn("cloudtrail", "trail", t_name)
                is_logging = trail.get("is_logging", True)

                # Flag log deletion / stopping as critical security alert
                security_alert = "LOG_STOPPED_OR_DELETED" if (not is_logging or action == "REMOVED") else "NORMAL"

                props = {
                    "Name": t_name,
                    "is_logging": is_logging,
                    "S3BucketName": trail.get("S3BucketName", ""),
                    "SecurityAlert": security_alert
                }

                self.add_node(
                    node_id=t_arn,
                    labels=["Resource", "CloudTrail", "Trail"],
                    change_type=action,
                    props=props
                )

                if trail.get("S3BucketName") and trail.get("S3BucketName") != "Unknown":
                    s3_bucket = trail.get("S3BucketName")
                    s3_arn = self.format_arn("s3", "bucket", s3_bucket)
                    self.add_node(
                        node_id=s3_arn,
                        labels=["Resource", "S3", "S3Bucket"],
                        change_type=action,
                        props={"BucketName": s3_bucket}
                    )
                    self.add_relationship(t_arn, s3_arn, "LOGS_TO_BUCKET", action)

    def process_diff(self, raw_diff: Dict[str, Any]) -> Dict[str, Any]:
        """Main normalization processing pipeline."""
        if "iam" in raw_diff:
            self.normalize_iam(raw_diff["iam"])
        if "s3" in raw_diff:
            self.normalize_s3(raw_diff["s3"])
        if "security_group" in raw_diff:
            self.normalize_security_groups(raw_diff["security_group"])
        if "cloudtrail" in raw_diff:
            self.normalize_cloudtrail(raw_diff["cloudtrail"])

        return {
            "summary": {
                "total_nodes": len(self.nodes),
                "total_relationships": len(self.relationships)
            },
            "graph": {
                "nodes": self.nodes,
                "relationships": self.relationships
            }
        }


def main():
    input_file = "diff.json"
    output_file = "normalized_diff.json"

    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    if len(sys.argv) > 2:
        output_file = sys.argv[2]

    # Strict File Existence Check
    if not os.path.exists(input_file):
        logger.error(f"Input diff file '{input_file}' not found.")
        raise FileNotFoundError(f"Required input file '{input_file}' does not exist.")

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            raw_diff = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from '{input_file}': {e}")
        raise

    normalizer = SchemaNormalizer()
    normalized_data = normalizer.process_diff(raw_diff)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(normalized_data, f, indent=2, ensure_ascii=False)

    logger.info(f"Normalization complete: {normalized_data['summary']['total_nodes']} nodes, {normalized_data['summary']['total_relationships']} relationships.")
    logger.info(f"Output saved to '{output_file}'")


if __name__ == "__main__":
    main()
