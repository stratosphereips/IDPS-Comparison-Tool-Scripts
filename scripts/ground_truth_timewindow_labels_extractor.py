import os
import shutil
import sys
import argparse

from parsers.ground_truth import GroundTruthParser


def parse_args():
    parser = argparse.ArgumentParser(description="Process the given ground "
                                                 "truth file and extracts "
                                                 "the label for each "
                                                 "timewindow.")
    
    parser.add_argument('-gtf', '--gtf_path', required=True, help="Output path for the operation.")
    parser.add_argument('-i', '--host_ip', required=True, help="IP address.")

    return parser.parse_args()
    
    
def main():
    args = parse_args()
    output_directory = 'output/ground_truth_timewindow_extractor'

    if os.path.exists(output_directory):
        shutil.rmtree(output_directory)

    os.makedirs(output_directory, exist_ok=True)
    results_path = os.path.join(output_directory, "results.txt")

    GroundTruthParser(
        output_directory,
        results_path,
        args.gtf_path,
        args.host_ip
        ).parse()
    
    
main()