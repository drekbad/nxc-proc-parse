#!/usr/bin/env python3
import argparse
import re
import sys

def parse_netexec_output(input_file, keywords):
    """
    Parses the output of netexec tasklist and sorts hosts based on keywords.

    Args:
        input_file (str): Path to the file containing netexec output.
        keywords (list): A list of lowercase strings to search for in process lists.

    Returns:
        tuple: A tuple containing three lists:
               (positive_hits, negative_hits, no_tasklist_hosts)
    """
    positive_hits = set()
    negative_hits = set()
    no_tasklist_hosts = set()

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[-] Error: Input file not found at '{input_file}'")
        sys.exit(1)

    # Use a regex to find all blocks of output, starting with the SMB header.
    # The (?s) flag makes '.' match newlines.
    # The 'SMB\s+[\d\.]+' part ensures we only start a block on a valid nxc header.
    host_blocks = re.split(r'(?=^SMB\s+[\d\.]+)', content, flags=re.MULTILINE)

    for block in host_blocks:
        if not block.strip():
            continue

        # Extract the IP address from the first line of the block
        ip_match = re.search(r'^SMB\s+([\d\.]+)', block)
        if not ip_match:
            continue
        
        current_ip = ip_match.group(1)
        block_lower = block.lower()

        # Check if the command actually returned a process list
        if "image name" in block_lower and "pid" in block_lower:
            # Search for any of the keywords in the block
            found = False
            for keyword in keywords:
                if keyword in block_lower:
                    positive_hits.add(current_ip)
                    found = True
                    break # Found a keyword, no need to check others for this host
            
            if not found:
                negative_hits.add(current_ip)
        else:
            # If we couldn't find the tasklist header, we can't make a determination
            no_tasklist_hosts.add(current_ip)
            
    # Return sorted lists for consistent output
    return sorted(list(positive_hits)), sorted(list(negative_hits)), sorted(list(no_tasklist_hosts))

def main():
    parser = argparse.ArgumentParser(
        description="Parse netexec (nxc) tasklist output to find hosts with or without specific processes.",
        epilog="Example: python3 parse_nxc_procs.py -i nxc_tasklist.txt -k sophos,crowdstrike,mcafee -o edr_results"
    )
    parser.add_argument("-i", "--input", required=True, help="Input file containing the raw nxc output.")
    parser.add_argument(
        "-k", "--keywords", required=True, 
        help="Comma-separated list of keywords to search for (e.g., 'sophos,sentinel,msmpeng'). Case-insensitive."
    )
    parser.add_argument(
        "-o", "--output", 
        help="Optional: Base name for output files. Will create '<basename>_positive.txt' and '<basename>_negative.txt'."
    )
    
    args = parser.parse_args()
    
    # Prepare keywords: split, strip whitespace, and convert to lowercase
    keywords_to_find = [k.strip().lower() for k in args.keywords.split(',')]
    if not any(keywords_to_find):
        print("[-] Error: No valid keywords provided.")
        sys.exit(1)

    positive, negative, unknown = parse_netexec_output(args.input, keywords_to_find)

    print("\n--- Scan Results ---")
    print(f"[+] Positive Hits (Keywords Found): {len(positive)}")
    print(f"[-] Negative Hits (No Keywords Found): {len(negative)}")
    print(f"[*] Unknown (No Tasklist Data): {len(unknown)}")
    print("--------------------\n")

    if positive:
        print("Hosts WITH specified processes:")
        for ip in positive:
            print(f"  - {ip}")
    
    if negative:
        print("\nHosts WITHOUT specified processes (potential targets):")
        for ip in negative:
            print(f"  - {ip}")

    if args.output:
        positive_filename = f"{args.output}_positive.txt"
        negative_filename = f"{args.output}_negative.txt"

        with open(positive_filename, 'w') as f:
            for ip in positive:
                f.write(f"{ip}\n")
        
        with open(negative_filename, 'w') as f:
            for ip in negative:
                f.write(f"{ip}\n")
        
        print(f"\n[+] Results written to '{positive_filename}' and '{negative_filename}'")

if __name__ == "__main__":
    main()
