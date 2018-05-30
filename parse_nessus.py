#!/usr/bin/env python

import re
import csv
import json
import argparse
from bs4 import BeautifulSoup


def main():
	parser = argparse.ArgumentParser(description="Script for converting Nessus HTML output into other formats")
	parser.add_argument('--input', required=True, help='Nessus HTML file to transform')
	parser.add_argument('--output', required=True, help='Destination file for output')
	parser.add_argument('--format', help='Output format', choices=['csv', 'json'], default='csv')

	args = parser.parse_args()
	
	with open(args.input, 'rb') as fh:
		html_data = fh.read()
	nessus_rows = parse_nessus_html(html_data)
	
	with open(args.output, 'wb') as fh:
		if args.format == 'csv':
			fieldnames = ["Vuln ID", "Title", "Synopsis", "Risk", "IP", "Protocol", "Port"]
			writer = csv.DictWriter(fh, fieldnames=fieldnames)
			writer.writeheader()
			writer.writerows(nessus_rows)
		elif args.format == 'json':
			fh.write(json.dumps(nessus_rows))
		
def parse_nessus_html(html_data):
	soup = BeautifulSoup(html_data, 'html.parser')
	vulns = soup.find_all(name='div', style=re.compile("""box-sizing: border-box; width: 100%; margin: 0 0 10px 0; padding: 5px 10px; background: #[0-9a-f]+; font-weight: bold; font-size: 14px; line-height: 20px; color: #fff;"""))

	rows = []
	for vuln in vulns:
		vuln_id = vuln.text.split(' ', 1)[0]
		vuln_title = vuln.text.split(' - ', 1)[1]
		synopsis_text = vuln.find_next(text="Synopsis").parent.find_next('div').find_next('div').text.strip()
		risk_text = vuln.find_next(text="Risk Factor").parent.find_next('div').find_next('div').text.strip()

		plugin_output_elem = vuln.find_next(text="Plugin Output").parent
		systems = []
		for sib in plugin_output_elem.next_siblings:
			if sib.name == 'h2' and "report output too big - ending list here" not in sib.text :
				ip, proto = sib.text.split(" ", 1)
				proto, port = proto.strip("()").split('/', 1)
				systems.append([ip, proto, port])
			elif sib.name == 'div' and 'id' in sib.attrs:
				# Next vuln
				break
		# Generate rows from the data:
		for ip, proto, port in systems:
			row = { "Vuln ID" : vuln_id,
					"Title" : vuln_title,
					"Synopsis" : synopsis_text,
					"Risk" : risk_text,
					"IP" : ip,
					"Protocol" : proto,
					"Port" : port
			}
			rows.append(row)
	return rows

		
if __name__ == "__main__":
	main()