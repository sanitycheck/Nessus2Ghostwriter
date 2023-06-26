import csv
import argparse
import xml.etree.ElementTree as ET
from typing import List, Tuple
import yaml

class Scanner:
    def __init__(self, parser: 'Parser') -> None:
        self.parser = parser

    def write_csv_file(self, file_path: str, data: List[List[str]]) -> None:
        # Open the output CSV file for writing
        with open(file_path, 'w', newline='', encoding='utf-8') as csv_file:
            # Create the CSV writer object
            csv_writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

            # Write the headers to the CSV file
            csv_writer.writerow(self.parser.headers)

            # Write the data to the CSV file
            for row in data:
                csv_writer.writerow(row)

            print(f'{len(data)} rows written to {file_path}')

    def write_output(self, file_path: str, data: List[List[str]], output_format: str) -> None:
        if output_format == 'csv':
            self.write_csv_file(file_path, data)
        elif output_format == 'yaml':
            self.write_yaml_file(file_path, data)
        else:
            raise ValueError(f'Invalid output format specified: {output_format}')

    def write_yaml_file(self, file_path: str, data: List[List[str]]) -> None:
        # Convert the data to a dictionary
        data_dict = []
        for row in data:
            data_dict.append(dict(zip(self.parser.headers, row)))

        # Write the dictionary to the YAML file
        with open(file_path, 'w', encoding='utf-8') as yaml_file:
            yaml.dump(data_dict, yaml_file)

        print(f'{len(data)} rows written to {file_path}')

    def run(self, output_file: str, output_format: str) -> None:
        # Parse the input file
        data = self.parser.parse_file()

        # Write the output file
        self.write_output(output_file, data, output_format)

class Parser:
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.headers = [ 'id',
                        'severity',
                        'finding_type',
                        'title',
                        'description',
                        'impact',
                        'mitigation',
                        'replication_steps',
                        'host_detection_techniques',
                        'network_detection_techniques',
                        'references',
                        'finding_guidance'
                        ]
# """         self.headers = ['title', 'description', 'severity', 'impact', 'mitigation',
#                         'replication_steps', 'host_detection_techniques',
#                         'network_detection_techniques', 'references', 'finding_type',
#                         'finding_guidance'] """

    def parse_file(self) -> Tuple[List[str], List[List[str]]]:
        raise NotImplementedError

class NessusParser(Parser):
    def parse_file(self) -> List[List[str]]:
        # Parse the .nessus XML file
        tree = ET.parse(self.file_path)
        root = tree.getroot()

        data = []
        vulns = []
        # Loop through all the report items and extract the data
        counter = 0
        for item in root.iter('ReportItem'):
            title = item.get('pluginName')
            description = item.find('description').text.strip()
            impact = ''
            severity = item.find('risk_factor').text.strip()
            if severity == 'None':
                severity = 'Informational'
            mitigation = item.find('solution').text.strip()
            replication_steps = ''
            host_detection_techniques = ''
            network_detection_techniques = ''
            references = ''
            if item.find('see_also') is not None:
                references = item.find('see_also').text.strip()
            finding_type = 'Network'
            finding_guidance = ''
            if title not in vulns:
                vulns.append(title)
                print(f"Processing {severity} - {title}...")
                # Add the data to the list

                data.append([counter,
                            severity,
                            finding_type,
                            title,
                            description,
                            impact,
                            mitigation,
                            replication_steps,
                            host_detection_techniques,
                            network_detection_techniques,
                            references,
                            finding_guidance])
            counter += 1

        return data

if __name__ == '__main__':
    # Parse the command-line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('file_path', help='Path to the input file')
    parser.add_argument('output_file', help='Path to the output file')
    parser.add_argument('--output-format', choices=['csv', 'yaml'], default='csv', help='Output format for the data')
    args = parser.parse_args()

    # Create the parser object
    myparser = NessusParser(args.file_path)

    # Create the scanner object
    scanner = Scanner(myparser)

    # Run the scanner
    scanner.run(args.output_file, args.output_format)
else:
    # Display the help message if no arguments are provided
    parser.print_help()
