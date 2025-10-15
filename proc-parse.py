#!/usr/bin/env python3
import argparse
import re
import sys
from collections import defaultdict

def parse_netexec_output(input_file, keywords, verbose=False):
    """
    Parses the output of netexec tasklist and sorts hosts based on keywords.
    This version correctly groups all lines for a single IP before processing.

    Args:
        input_file (str): Path to the file containing netexec output.
        keywords (list): A list of lowercase strings to search for in process lists.
        verbose (bool): If True, prints detailed classification reasons.

    Returns:
        tuple: A tuple containing three sets:
               (positive_hits, negative_hits, no_tasklist_hosts)
    """
    host_data = defaultdict(str)

    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # Use regex to find the IP on any line starting with SMB
                ip_match = re.search(r'^SMB\s+([\d\.]+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    # Append the entire line to the data for that IP
                    host_data[ip] += line + '\n'
    except FileNotFoundError:
        print(f"[-] Error: Input file not found at '{input_file}'")
        sys.exit(1)

    positive_hits = set()
    negative_hits = set()
    no_tasklist_hosts = set()

    # Now, process the fully assembled blocks of data for each host
    for ip, block_text in host_data.items():
        block_lower = block_text.lower()

        # Check if the command actually returned a process list header
        if "image name" in block_lower and "pid" in block_lower:
            found_keyword = False
            for keyword in keywords:
                if keyword in block_lower:
                    positive_hits.add(ip)
                    if verbose:
                        print(f"[v] CLASSIFIED [+]: Found '{keyword}' for host {ip}")
                    found_keyword = True
                    break  # Found one, no need to check others

            if not found_keyword:
                negative_hits.add(ip)
                if verbose:
                    print(f"[v] CLASSIFIED [-]: No keywords found for host {ip}")
        else:
            no_tasklist_hosts.add(ip)
            if verbose:
                # Check if it was a pwned host that just failed the command
                if "pwn3d!" in block_lower:
                     print(f"[v] CLASSIFIED [*]: Host {ip} was pwn3d, but tasklist command failed or returned no output.")
                else:
                     print(f"[v] CLASSIFIED [*]: Could not get tasklist for host {ip} (likely auth failure or other error).")

    return positive_hits, negative_hits, no_tasklist_hosts

def main():
    parser = argparse.ArgumentParser(
        description="Parse netexec (nxc) tasklist output to find hosts with or without specific processes (v2).",
        epilog="Example: python3 parse_nxc_procs_v2.py -i nxc_tasklist.txt -k sophos,crowdstrike -o edr_results -v"
    )
    parser.add_argument("-i", "--input", required=True, help="Input file containing the raw nxc output.")
    parser.add_argument(
        "-k", "--keywords", required=True,
        help="Comma-separated list of keywords (e.g., 'sophos,sentinel,msmpeng'). Case-insensitive."
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional: Base name for output files. Creates '<basename>_positive.txt' and '<basename>_negative.txt'."
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose mode to see how each host is classified."
    )

    args = parser.parse_args()

    keywords_to_find = [k.strip().lower() for k in args.keywords.split(',') if k.strip()]
    if not keywords_to_find:
        print("[-] Error: No valid keywords provided.")
        sys.exit(1)

    positive, negative, unknown = parse_netexec_output(args.input, keywords_to_find, args.verbose)
    
    # Sort for consistent output
    positive_list = sorted(list(positive))
    negative_list = sorted(list(negative))
    unknown_list = sorted(list(unknown))

    print("\n" + "="*25)
    print("---      Scan Summary     ---")
    print("="*25)
    print(f"[+] Positive Hits (Keywords Found)  : {len(positive_list)}")
    print(f"[-] Negative Hits (No Keywords Found): {len(negative_list)}")
    print(f"[*] Unknown (No Tasklist Data)      : {len(unknown_list)}")
    print(f"Total Unique IPs Processed: {len(positive_list) + len(negative_list) + len(unknown_list)}")
    print("="*25 + "\n")

    if positive_list:
        print("--- Hosts WITH specified processes ---")
        for ip in positive_list:
            print(f"  [+] {ip}")

    if negative_list:
        print("\n--- Hosts WITHOUT specified processes (POTENTIAL TARGETS) ---")
        for ip in negative_list:
            print(f"  [-] {ip}")

    if args.output:
        positive_filename = f"{args.output}_positive.txt"
        negative_filename = f"{args.output}_negative.txt"

        with open(positive_filename, 'w') as f:
            f.write('\n'.join(positive_list) + '\n')

        with open(negative_filename, 'w') as f:
            f.write('\n'.join(negative_list) + '\n')

        print(f"\n[+] Results written to '{positive_filename}' and '{negative_filename}'")

if __name__ == "__main__":
    main()
