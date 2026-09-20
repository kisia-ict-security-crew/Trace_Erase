"""
diff_to_cypher-v4.py - AWS Security Snapshot Analysis Pipeline (VPC as Property)
Converts raw diff.json into Cypher queries. VPCs are downgraded to properties
to reduce graph visual noise.
"""

import json
import logging
import os
import sys
import argparse
from typing import Dict, List, Any

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("diff_to_cypher")


def escape_cypher_value(val: Any) -> str:
    if isinstance(val, bool): return "true" if val else "false"
    elif isinstance(val, (int, float)): return str(val)
    elif val is None: return "null"
    elif isinstance(val, (dict, list)):
        s = json.dumps(val).replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"').replace("\n", "\\n")
        return f'"{s}"'
    else:
        s = str(val).replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"').replace("\n", "\\n")
        return f'"{s}"'


def extract_nodes_and_rels(diff_data: Dict[str, Any]):
    nodes = []
    relationships = []

    def add_node(node_id: str, label: str, change_type: str, props: dict):
        if not node_id: return
        nodes.append({
            "id": node_id,
            "labels": ["Resource", label],
            "change_type": change_type,
            "properties": props
        })

    def add_rel(src_id: str, tgt_id: str, rel_type: str, change_type: str):
        if not src_id or not tgt_id: return
        relationships.append({
            "source": src_id,
            "target": tgt_id,
            "type": rel_type,
            "change_type": change_type,
            "properties": {}
        })

    # 1. Parse Security Groups
    for change_type in ["added", "removed", "modified"]:
        for sg in diff_data.get("security_group", {}).get(change_type, []):
            sg_id = sg.get("group_id")
            props = {"group_name": sg.get("group_name"), "description": sg.get("description")}
            # VPC를 엣지(Relationship)가 아닌 속성(Property)으로 편입
            if sg.get("vpc_id"):
                props["vpc_id"] = sg.get("vpc_id")
            
            add_node(sg_id, "SecurityGroup", change_type.upper(), props)

    # 2. Parse VPCs and networking resources
    for change_type in ["added", "removed", "modified"]:
        for item in diff_data.get("vpc", {}).get(change_type, []):
            
            def process_resource(res, cat=""):
                # 1. Subnet
                if cat == "subnets" or "subnet_id" in res:
                    sub_id = res.get("subnet_id")
                    props = {"cidr_block": res.get("cidr_block"), "az": res.get("availability_zone")}
                    if res.get("vpc_id"): props["vpc_id"] = res.get("vpc_id")
                    add_node(sub_id, "Subnet", change_type.upper(), props)
                
                # 2. VPC (노드로 생성하지 않고 무시함 - 속성으로만 존재)
                elif cat == "vpcs" or ("vpc_id" in res and "cidr_block" in res):
                    pass 
                
                # 3. Route Table
                elif cat == "route_tables" or "route_table_id" in res:
                    rt_id = res.get("route_table_id")
                    props = {}
                    if res.get("vpc_id"): props["vpc_id"] = res.get("vpc_id")
                    add_node(rt_id, "RouteTable", change_type.upper(), props)
                
                # 4. Internet Gateway
                elif cat == "internet_gateways" or "internet_gateway_id" in res:
                    igw_id = res.get("internet_gateway_id")
                    props = {}
                    attached_vpcs = [att.get("vpc_id") for att in res.get("attachments", []) if att.get("vpc_id")]
                    if attached_vpcs:
                        props["attached_vpc_ids"] = ",".join(attached_vpcs)
                    add_node(igw_id, "InternetGateway", change_type.upper(), props)
                
                # 5. Network ACL
                elif cat == "network_acls" or "network_acl_id" in res:
                    nacl_id = res.get("network_acl_id")
                    props = {"is_default": res.get("is_default")}
                    if res.get("vpc_id"): props["vpc_id"] = res.get("vpc_id")
                    add_node(nacl_id, "NetworkAcl", change_type.upper(), props)
                    
                    # 서브넷과의 연관성은 중요한 토폴로지 정보이므로 엣지(Relationship) 유지
                    for assoc in res.get("associations", []):
                        if assoc.get("subnet_id"): 
                            add_rel(nacl_id, assoc.get("subnet_id"), "ASSOCIATED_WITH_SUBNET", change_type.upper())

            # 중첩 구조인지 확인
            is_wrapper = any(k in item for k in ["vpcs", "subnets", "route_tables", "internet_gateways", "network_acls"])
            
            if is_wrapper:
                for cat_key, sub_items in item.items():
                    if isinstance(sub_items, list):
                        for sub_item in sub_items:
                            if isinstance(sub_item, dict):
                                process_resource(sub_item, cat=cat_key)
            else:
                cat = item.get("_resource_type_category", "")
                process_resource(item, cat)

    return nodes, relationships


def generate_cypher(diff_data: Dict[str, Any]) -> List[str]:
    cypher_statements = [
        "// =========================================================",
        "// AWS Infrastructure Security Graph - Generated Cypher Script",
        "// (VPC downgraded to properties to reduce visual noise)",
        "// =========================================================",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (r:Resource) REQUIRE r.id IS UNIQUE;"
    ]

    nodes, relationships = extract_nodes_and_rels(diff_data)

    if nodes:
        cypher_statements.append("\n// --- 1. Nodes Creation & Update ---")
        for node in nodes:
            node_id = node.get("id")
            labels = ":".join(node.get("labels", ["Resource"]))
            change_type = node.get("change_type", "ADDED")
            props = node.get("properties", {})
            props["id"] = node_id
            props["change_type"] = change_type

            if change_type in ["ADDED", "MODIFIED"]:
                prop_str_list = [f"{k}: {escape_cypher_value(v)}" for k, v in props.items()]
                prop_clause = "{" + ", ".join(prop_str_list) + "}"
                cypher = f"MERGE (n:{labels} {{id: {escape_cypher_value(node_id)}}}) ON CREATE SET n = {prop_clause} ON MATCH SET n += {prop_clause};"
                cypher_statements.append(cypher)
            elif change_type == "REMOVED":
                cypher = f"MATCH (n {{id: {escape_cypher_value(node_id)}}}) SET n.status = \"DELETED\", n.change_type = \"REMOVED\";"
                cypher_statements.append(cypher)

    if relationships:
        cypher_statements.append("\n// --- 2. Relationships Creation ---")
        for rel in relationships:
            source_id = rel.get("source")
            target_id = rel.get("target")
            rel_type = rel.get("type", "CONNECTED_TO")
            change_type = rel.get("change_type", "ADDED")
            props = rel.get("properties", {})
            props["change_type"] = change_type

            prop_str_list = [f"{k}: {escape_cypher_value(v)}" for k, v in props.items()]
            prop_clause = "{" + ", ".join(prop_str_list) + "}" if prop_str_list else "{}"

            if change_type in ["ADDED", "MODIFIED"]:
                cypher = (
                    f"MERGE (src:Resource {{id: {escape_cypher_value(source_id)}}}) "
                    f"MERGE (tgt:Resource {{id: {escape_cypher_value(target_id)}}}) "
                    f"MERGE (src)-[r:{rel_type}]->(tgt) "
                    f"SET r += {prop_clause};"
                )
                cypher_statements.append(cypher)
            elif change_type == "REMOVED":
                cypher = (
                    f"MATCH (src {{id: {escape_cypher_value(source_id)}}})-[r:{rel_type}]->(tgt {{id: {escape_cypher_value(target_id)}}}) "
                    f"SET r.status = \"DELETED\", r.change_type = \"REMOVED\";"
                )
                cypher_statements.append(cypher)

    return cypher_statements


def main():
    parser = argparse.ArgumentParser(description="Convert raw diff.json to Cypher queries for Neo4j.")
    parser.add_argument("--input", default="diff.json", help="Path to diff.json input file")
    parser.add_argument("--output", default="diff.cypher", help="Path to output diff.cypher file")
    args = parser.parse_args()

    input_file = args.input
    output_file = args.output

    if not os.path.exists(input_file):
        logger.error(f"Input file '{input_file}' not found.")
        sys.exit(1)

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            diff_data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from '{input_file}': {e}")
        sys.exit(1)

    logger.info(f"Loaded diff from '{input_file}'. Generating Cypher queries (VPC reduced)...")
    cypher_queries = generate_cypher(diff_data)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(cypher_queries) + "\n")

    logger.info(f"Successfully generated Cypher script -> '{output_file}'")


if __name__ == "__main__":
    main()