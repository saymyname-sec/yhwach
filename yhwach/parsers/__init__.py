"""Ingestion parsers. Each parser is deterministic: same input -> same rows."""
from yhwach.parsers.nmap import ParsedHost, ParsedService, insert_hosts, parse_nmap_xml

__all__ = ["parse_nmap_xml", "insert_hosts", "ParsedHost", "ParsedService"]
