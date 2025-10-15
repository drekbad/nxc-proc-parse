#!/usr/bin/env python3
import argparse
import re
import sys
from collections import defaultdict

def parse_netexec_output(input_file, keywords, verbose=False):
    """
    Parses the output of netexec tasklist and sorts hosts based on keywords.
    This version provides detailed reporting on which keywords were found per host.

    Args:
        input_file (str): Path to the file containing netexec output.
        keywords (list): A list of lowercase strings to search for in process lists.
        verbose (bool): If True, prints detailed classification reasons.

    Returns:
        tuple: A tuple containing three items:
               (positive_hits_details, negative_hits, no_tasklist_hosts)
               positive_hits_details is a dict: {ip: {found_keyword1, ...}}
    """
    host_data = defaultdict(str)

    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                ip_match = re.search(r'^SMB\s+([\d\.]+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    host_data[ip] += line + '\n'
    except FileNotFoundError:
        print(f"[-] Error: Input file not found at '{input_file}'")
        sys.exit(1)

    positive_hits_details = defaultdict(set)
    negative_hits = set()
    no_tasklist_hosts = set()

    for ip, block_text in host_data.items():
        block_lower = block_text.lower()

        if "image name" in block_lower and "pid" in block_lower:
            found_keywords_for_ip = set()
            for keyword in keywords:
                if keyword in block_lower:
                    found_keywords_for_ip.add(keyword)

            if found_keywords_for_ip:
                positive_hits_details[ip] = found_keywords_for_ip
                if verbose:
                    hits_str = ", ".join(found_keywords_for_ip)
                    print(f"[v] CLASSIFIED [+]: Found '{hits_str}' for host {ip}")
            else:
                negative_hits.add(ip)
                if verbose:
                    print(f"[v] CLASSIFIED [-]: No keywords found for host {ip}")
        else:
            no_tasklist_hosts.add(ip)
            if verbose:
                if "pwn3d!" in block_lower:
                     print(f"[v] CLASSIFIED [*]: Host {ip} was pwn3d, but tasklist failed or returned no output.")
                else:
                     print(f"[v] CLASSIFIED [*]: Could not get tasklist for host {ip} (likely auth failure).")

    return positive_hits_details, negative_hits, no_tasklist_hosts

def main():
    parser = argparse.ArgumentParser(
        description="Parse netexec (nxc) tasklist output to find hosts with or without specific processes (v3).",
        epilog="Example: python3 parse_nxc_procs_v3.py -i nxc.txt -k sophos,crowdstrike,carbon -o edr_detailed"
    )
    # ... (rest of the arguments are the same as v2)
    parser.add_argument("-i", "--input", required=True, help="Input file containing the raw nxc output.")
    parser.add_argument(
        "-k", "--keywords", required=True,
        help="Comma-separated list of keywords (e.g., 'sophos,sentinel,msmpeng'). Case-insensitive."
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional: Base name for output files. Creates '<basename>_positive_detailed.txt' and '<basename>_negative.txt'."
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

    positive_details, negative, unknown = parse_netexec_output(args.input, keywords_to_find, args.verbose)
    
    # Sort for consistent output
    positive_sorted_ips = sorted(positive_details.keys())
    negative_list = sorted(list(negative))
    unknown_list = sorted(list(unknown))

    print("\n" + "="*35)
    print("---         Scan Summary          ---")
    print("="*35)
    print(f"[+] Positive Hits (Keywords Found)  : {len(positive_sorted_ips)}")
    print(f"[-] Negative Hits (No Keywords Found): {len(negative_list)}")
    print(f"[*] Unknown (No Tasklist Data)      : {len(unknown_list)}")
    print(f"Total Unique IPs Processed          : {len(positive_sorted_ips) + len(negative_list) + len(unknown_list)}")
    print("---      Keyword Breakdown      ---")

    keyword_counts = defaultdict(int)
    for found_sets in positive_details.values():
        for keyword in found_sets:
            keyword_counts[keyword] += 1
    
    if not keyword_counts:
        print("    (No keywords found on any host)")
    else:
        for keyword in keywords_to_find: # Print in original order
             count = keyword_counts[keyword]
             print(f"    - '{keyword}': {count} hosts")
    print("="*35 + "\n")


    print("--- Hosts WITH specified processes ---")
    if positive_sorted_ips:
        for ip in positive_sorted_ips:
            found_keywords = ", ".join(sorted(list(positive_details[ip])))
            print(f"  [+] {ip}: {found_keywords}")
    else:
        print("  (No hosts found in this category)")


    print("\n--- Hosts WITHOUT specified processes (POTENTIAL TARGETS) ---")
    if negative_list:
        for ip in negative_list:
            print(f"  [-] {ip}")
    else:
        print("  (No hosts found in this category)")


    if args.output:
        positive_filename = f"{args.output}_positive_detailed.txt"
        negative_filename = f"{args.output}_negative.txt"

        with open(positive_filename, 'w') as f:
            f.write("IP;KeywordsFound\n") # Add a header
            for ip in positive_sorted_ips:
                found_keywords_str = ",".join(sorted(list(positive_details[ip])))
                f.write(f"{ip};{found_keywords_str}\n")
        
        with open(negative_filename, 'w') as f:
            f.write('\n'.join(negative_list) + '\n')
        
        print(f"\n[+] Results written to '{positive_filename}' and '{negative_filename}'")

if __name__ == "__main__":
    main()
