"""
neo4j_loader-v3.py - AWS Security Snapshot Analysis Pipeline (Refactored v3)
Loads generated Cypher queries (diff.cypher) into Neo4j Graph Database safely without comment execution errors.
"""

import argparse
import logging
import os
import sys

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("neo4j_loader")


class Neo4jGraphLoader:
    """Handles connection and batch Cypher query execution against Neo4j DB."""

    def __init__(self, uri: str, user: str, passw: str):
        self.uri = uri
        self.user = user
        self.passw = passw
        self.driver = None

    def connect(self):
        """Establish connection to Neo4j instance."""
        try:
            from neo4j import GraphDatabase, exceptions
        except ImportError:
            logger.error("The 'neo4j' Python driver is not installed. Please install it via: pip install neo4j")
            sys.exit(1)

        try:
            logger.info(f"Connecting to Neo4j database at '{self.uri}'...")
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.passw))
            self.driver.verify_connectivity()
            logger.info("Successfully connected and verified Neo4j connection.")
        except exceptions.Neo4jError as e:
            logger.error(f"Failed to connect to Neo4j database: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected connection error: {e}")
            raise

    def close(self):
        """Close driver connection."""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection driver closed.")

    @staticmethod
    def _clean_and_validate_statement(stmt: str) -> str:
        """Strip single-line comments and return executable Cypher code."""
        lines = [line for line in stmt.splitlines() if not line.strip().startswith("//")]
        return "\n".join(lines).strip()

    def execute_cypher_script(self, script_path: str):
        """Read and execute Cypher statements from script_path."""
        if not os.path.exists(script_path):
            logger.error(f"Cypher script file '{script_path}' not found.")
            raise FileNotFoundError(f"Required input Cypher file '{script_path}' does not exist.")

        logger.info(f"Reading Cypher script from '{script_path}'...")
        with open(script_path, "r", encoding="utf-8") as f:
            cypher_content = f.read()

        # Split individual Cypher statements by semicolon
        raw_statements = cypher_content.split(";")
        executable_statements = []

        for stmt in raw_statements:
            cleaned = self._clean_and_validate_statement(stmt)
            if cleaned:
                executable_statements.append(cleaned)

        if not executable_statements:
            logger.warning("No executable Cypher statements found in file.")
            return

        logger.info(f"Found {len(executable_statements)} executable Cypher statements to run.")

        success_count = 0
        error_count = 0

        try:
            from neo4j import exceptions
        except ImportError:
            logger.error("The 'neo4j' Python driver is not installed.")
            sys.exit(1)

        with self.driver.session() as session:
            for idx, stmt in enumerate(executable_statements, 1):
                try:
                    session.run(stmt)
                    success_count += 1
                except exceptions.CypherSyntaxError as e:
                    logger.error(f"Syntax error in Cypher statement #{idx}: {e}")
                    logger.debug(f"Failed statement text: {stmt}")
                    error_count += 1
                except exceptions.Neo4jError as e:
                    logger.error(f"Database error executing statement #{idx}: {e}")
                    error_count += 1
                except Exception as e:
                    logger.error(f"Unexpected error executing statement #{idx}: {e}")
                    error_count += 1

        logger.info(f"Cypher script execution complete. Success: {success_count}, Failures: {error_count}")
        if error_count > 0:
            logger.warning(f"Completed with {error_count} errors.")


def main():
    parser = argparse.ArgumentParser(description="Load Cypher script into Neo4j Graph Database.")
    parser.add_argument("--uri", default=os.getenv("NEO4J_URI", "bolt://localhost:7687"), help="Neo4j connection URI (Default: bolt://localhost:7687)")
    parser.add_argument("--user", default=os.getenv("NEO4J_USER", "neo4j"), help="Neo4j username (Default: neo4j)")
    parser.add_argument("--password", default=os.getenv("NEO4J_PASSWORD", "password"), help="Neo4j password")
    parser.add_argument("--input", default="diff.cypher", help="Path to input diff.cypher file (Default: diff.cypher)")

    args = parser.parse_args()

    loader = Neo4jGraphLoader(uri=args.uri, user=args.user, passw=args.password)
    try:
        loader.connect()
        loader.execute_cypher_script(args.input)
    finally:
        loader.close()


if __name__ == "__main__":
    main()
