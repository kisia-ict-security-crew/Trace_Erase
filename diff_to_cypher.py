"""
diff_to_cypher-v4.py - AWS Security Snapshot Analysis Pipeline (Refactored v4)
Converts normalized_diff.json into executable Cypher queries for Neo4j.
"""

import json
import logging
import os
import sys
import argparse
from typing import Dict, List, Any

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("diff_to_cypher")


def escape_cypher_value(val: Any) -> str:
    """Safely format values for Cypher query strings."""
    if isinstance(val, bool):
        return "true" if val else "false"
    elif isinstance(val, (int, float)):
        return str(val)
    elif val is None:
        return "null"
    else:
        # Escape backslashes, quotes, and newlines
        s = str(val).replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"').replace("\n", "\\n")
        return f'"{s}"'


def generate_cypher(normalized_data: Dict[str, Any]) -> List[str]:
    """Convert normalized graph nodes and relationships into Cypher statements."""
    cypher_statements = [
        "// =========================================================",
        "// AWS Infrastructure Security Graph - Generated Cypher Script",
        "// =========================================================",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (r:Resource) REQUIRE r.id IS UNIQUE;"
    ]

    graph = normalized_data.get("graph", {})
    nodes = graph.get("nodes", [])
    relationships = graph.get("relationships", [])

    # 1. Process Nodes
    if nodes:
        cypher_statements.append("// --- 1. Nodes Creation & Update ---")
        for node in nodes:
            node_id = node.get("id")
            if not node_id:
                continue

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

    # 2. Process Relationships
    if relationships:
        cypher_statements.append("// --- 2. Relationships Creation ---")
        for rel in relationships:
            source_id = rel.get("source")
            target_id = rel.get("target")
            rel_type = rel.get("type", "CONNECTED_TO")
            change_type = rel.get("change_type", "ADDED")
            props = rel.get("properties", {})
            props["change_type"] = change_type

            if not source_id or not target_id:
                continue

            prop_str_list = [f"{k}: {escape_cypher_value(v)}" for k, v in props.items()]
            prop_clause = "{" + ", ".join(prop_str_list) + "}" if prop_str_list else "{}"

            # MERGE both source and target nodes so relationships are ALWAYS created even if target node was omitted
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
    parser = argparse.ArgumentParser(description="Convert normalized_diff.json to Cypher queries for Neo4j.")
    parser.add_argument("--input", default="normalized_diff.json", help="Path to normalized_diff.json input file")
    parser.add_argument("--output", default="diff.cypher", help="Path to output diff.cypher file")
    args = parser.parse_args()

    input_file = args.input
    output_file = args.output

    if not os.path.exists(input_file):
        logger.error(f"Input file '{input_file}' not found.")
        raise FileNotFoundError(f"Required input file '{input_file}' does not exist.")

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            normalized_data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from '{input_file}': {e}")
        raise

    logger.info(f"Loaded normalized diff from '{input_file}'. Generating Cypher queries...")
    cypher_queries = generate_cypher(normalized_data)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(cypher_queries) + "\n")

    logger.info(f"Successfully generated Cypher script -> '{output_file}'")


if __name__ == "__main__":
    main()
