import argparse
import csv
import json
import os
import re
import urllib.request

# Try to import official libraries, but we will write custom regex-based parser
# for STIX JSON to ensure the script works even without installing pip packages.
try:
    from stix2 import TAXIICollectionSource
    from taxii2client.v20 import Collection
    HAS_STIX_LIBS = True
except ImportError:
    HAS_STIX_LIBS = False

def parse_stix_pattern(pattern):
    # Extracts IP or hash from STIX patterns
    # e.g., "[ipv4-addr:value = '192.168.1.5']" -> ('ip', '192.168.1.5')
    # e.g., "[file:hashes.'SHA-256' = '7f3a9c2e5d0b4aa88d21f18b0f715b66']" -> ('hash', '7f3a9c2e5d0b4aa88d21f18b0f715b66')
    ip_match = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
    if ip_match:
        return 'ip', ip_match.group(1)
        
    hash_match = re.search(r"file:hashes\.(?:'SHA-256'|\"SHA-256\")\s*=\s*'([^']+)'", pattern)
    if hash_match:
        return 'hash', hash_match.group(1)
        
    hash_md5 = re.search(r"file:hashes\.(?:'MD5'|\"MD5\")\s*=\s*'([^']+)'", pattern)
    if hash_md5:
        return 'hash', hash_md5.group(1)
        
    return None, None

def parse_stix_bundle(bundle_data):
    iocs = []
    objects = bundle_data.get("objects", [])
    
    for obj in objects:
        if obj.get("type") == "indicator":
            pattern = obj.get("pattern", "")
            ioc_type, ioc_value = parse_stix_pattern(pattern)
            
            if ioc_type and ioc_value:
                # Determine malware family from tags or description
                desc = obj.get("description", "Imported STIX Indicator")
                malware_family = "Unknown"
                
                # Look for malware family naming patterns in description or labels
                for label in obj.get("labels", []):
                    if label.lower() not in ("malicious-activity", "indicator", "threat-intel"):
                        malware_family = label.upper()
                        break
                
                family_match = re.search(r"(triton|trisis|stuxnet|industroyer|blackenergy|havex|pipedream)", desc, re.IGNORECASE)
                if family_match:
                    malware_family = family_match.group(1).upper()
                
                # Determine severity
                severity = "high"
                if "critical" in desc.lower() or "critical" in pattern.lower():
                    severity = "critical"
                elif "low" in desc.lower():
                    severity = "medium"
                
                iocs.append({
                    "type": ioc_type,
                    "value": ioc_value,
                    "severity": severity,
                    "malware_family": malware_family,
                    "description": desc
                })
    return iocs

def fetch_from_taxii(url, collection_id, username=None, password=None):
    if not HAS_STIX_LIBS:
        print("Error: taxii2-client and stix2 libraries are required for direct TAXII communication.")
        print("Please install them: pip install stix2 taxii2-client")
        return []
        
    print(f"Connecting to TAXII server: {url}...")
    # This represents standard TAXII v2 API client connection
    try:
        collection_url = f"{url.rstrip('/')}/collections/{collection_id}/"
        collection = Collection(collection_url, user=username, password=password)
        source = TAXIICollectionSource(collection)
        
        # Query indicators
        indicators = source.query([
            {"field": "type", "op": "=", "value": "indicator"}
        ])
        
        iocs = []
        for ind in indicators:
            ioc_type, ioc_value = parse_stix_pattern(ind.pattern)
            if ioc_type and ioc_value:
                iocs.append({
                    "type": ioc_type,
                    "value": ioc_value,
                    "severity": getattr(ind, "confidence", 80) >= 90 and "critical" or "high",
                    "malware_family": len(getattr(ind, "labels", [])) > 0 and ind.labels[0].upper() or "UNKNOWN",
                    "description": getattr(ind, "description", "TAXII Streamed IOC")
                })
        return iocs
    except Exception as e:
        print(f"TAXII fetch error: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description="ThreatFusion STIX/TAXII Threat Intel Ingestion Tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="Path to local STIX 2.x JSON bundle file")
    group.add_argument("--taxii-url", help="TAXII server v2 Discovery or API root URL")
    group.add_argument("--public-feed", choices=["otx-simulation"], help="Fetch OTX/threat list simulation bundle")
    
    parser.add_argument("--collection-id", help="TAXII Collection ID (required for TAXII URL)")
    parser.add_argument("--output", default="data/iocs.csv", help="Path to ThreatIntel CSV file to update")
    args = parser.parse_args()

    iocs = []
    
    if args.file:
        print(f"Reading STIX bundle from: {args.file}")
        with open(args.file, "r", encoding="utf-8") as f:
            bundle_data = json.load(f)
            iocs = parse_stix_bundle(bundle_data)
            
    elif args.taxii_url:
        if not args.collection_id:
            print("Error: --collection-id is required when using --taxii-url")
            return
        iocs = fetch_from_taxii(args.taxii_url, args.collection_id)
        
    elif args.public_feed == "otx-simulation":
        # Simulate download of public OTX STIX feed with Triton and Stuxnet indicators
        print("Generating mock/simulated STIX feed containing public ICS indicators...")
        simulated_bundle = {
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "pattern": "[ipv4-addr:value = '192.168.1.250']",
                    "description": "Known Triton command and control staging pivot host",
                    "labels": ["triton", "malicious-activity"]
                },
                {
                    "type": "indicator",
                    "pattern": "[file:hashes.'SHA-256' = 'a123bc456de7890123456789abcdef0123456789abcdef0123456789abcdef01']",
                    "description": "Stuxnet binary component file hash detected in wild",
                    "labels": ["stuxnet", "malicious-activity"]
                }
            ]
        }
        iocs = parse_stix_bundle(simulated_bundle)

    if not iocs:
        print("No indicators extracted.")
        return

    print(f"Extracted {len(iocs)} indicators.")
    
    # Read existing IOCs to avoid duplicates
    existing_values = set()
    if os.path.exists(args.output):
        with open(args.output, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                existing_values.add(row.get("value", ""))

    # Append new IOCs to file
    new_count = 0
    file_exists = os.path.exists(args.output)
    
    with open(args.output, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["type", "value", "severity", "malware_family", "description"])
        if not file_exists:
            writer.writeheader()
            
        for ioc in iocs:
            if ioc["value"] not in existing_values:
                writer.writerow(ioc)
                existing_values.add(ioc["value"])
                new_count += 1
                
    print(f"Ingestion complete. Added {new_count} new unique IOCs to: {args.output}")

if __name__ == "__main__":
    main()
