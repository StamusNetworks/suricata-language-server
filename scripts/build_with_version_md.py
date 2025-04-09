"""
Copyright(C) 2025 Stamus Networks

This file is part of Suricata Language Server.

Suricata Language Server is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Suricata Language Server is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Suricata Language Server.  If not, see <http://www.gnu.org/licenses/>.
"""

import csv
import os
import re
import json
from collections import defaultdict
from packaging import version
import argparse

def extract_semver(filename):
    """Extract semantic version from filename like 'data_v1.2.3.csv'."""
    match = re.search(r'v(\d+\.\d+\.\d+)', filename)
    return version.parse(match.group(1)) if match else None

def process_csv_files(folder_path):
    item_versions = defaultdict(set)
    item_rows = {}
    all_versions = set()
    header_saved = None

    files_list = os.listdir(folder_path)
    files_list.sort(reverse=True)
    for filename in files_list:
        if filename.endswith(".csv"):
            semver = extract_semver(filename)
            if semver is None:
                continue

            all_versions.add(semver)

            filepath = os.path.join(folder_path, filename)
            with open(filepath, newline='', encoding='utf-8') as csvfile:
                reader = csv.reader(csvfile, delimiter=';')
                header = next(reader, None)
                if header_saved is None:
                    header_saved = [h.strip() for h in header]

                for row in reader:
                    if not row or len(row) == 0:
                        continue

                    # Normalize: strip and remove trailing empty cells
                    row = [cell.strip() for cell in row]
                    if row[-1] == "":
                        row.pop()

                    item = row[0]

                    # Track versions and earliest row
                    item_versions[item].add(semver)
                    if item not in item_rows or semver > item_rows[item][0]:
                        item_rows[item] = (semver, row)

    latest_version = max(all_versions)

    results = []
    for item, versions in item_versions.items():
        initial_version = min(versions)
        last_version = max(versions)
        row_data = item_rows[item][1]
        results.append({
            "row": row_data,
            "initial_version": str(initial_version),
            "last_version": str(last_version)
        })

    return header_saved, results

def write_csv_output(header, results, output_file):
    with open(output_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(header + ["initial_version", "last_version"])
        for entry in sorted(results, key=lambda x: x["row"][0]):
            writer.writerow(entry["row"] + [entry["initial_version"], entry["last_version"]])

def write_json_output(header, results, output_file):
    json_data = []
    for entry in results:
        item_dict = {header[i]: entry["row"][i] for i in range(len(entry["row"]))}
        item_dict["initial_version"] = entry["initial_version"]
        item_dict["last_version"] = entry["last_version"]
        json_data.append(item_dict)

    with open(output_file, mode='w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)

def write_markdown_output(header, results, output_file):
    with open(output_file, mode='w', encoding='utf-8') as f:
        # Prepare header row
        md_header = header + ["initial_version", "last_version"]
        f.write("| " + " | ".join(md_header) + " |\n")
        f.write("|" + "|".join(["---"] * len(md_header)) + "|\n")

        for entry in sorted(results, key=lambda x: x["row"][0]):
            row = entry["row"]
            # Replace last column (URL) with markdown link
            if row:
                url = row[-1]
                row = row[:-1] + [f"[Doc]({url})"]
            md_row = row + [entry["initial_version"], entry["last_version"]]
            f.write("| " + " | ".join(md_row) + " |\n")

def main():
    parser = argparse.ArgumentParser(description="Merge CSVs with version tracking.")
    parser.add_argument("--input-dir", required=True, help="Directory containing input CSV files")
    parser.add_argument("--output-prefix", required=True, help="Prefix for output files (no extension)")
    parser.add_argument("--output-format", choices=["csv", "json", "md"], default="json", help="Output format")

    args = parser.parse_args()
    input_folder = args.input_dir
    prefix = args.output_prefix


    header, results = process_csv_files(input_folder)

    if args.output_format == "csv":
        output_csv = f"{prefix}.csv"
        write_csv_output(header, results, output_csv)
        print(f"✅ CSV written to: {output_csv}")
    elif args.output_format == "json":
        output_json = f"{prefix}.json"
        write_json_output(header, results, output_json)
        print(f"✅ JSON written to: {output_json}")
    elif args.output_format == "md":
        output_md = f"{prefix}.md"
        write_markdown_output(header, results, output_md)
        print(f"✅ Markdown written to: {output_md}")


if __name__ == "__main__":
    main()
