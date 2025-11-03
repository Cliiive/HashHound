import argparse
import os
import sys
from pathlib import Path


class ArgumentParser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="HashHound - Evidence Analysis Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  python main.py --evidence /path/to/evidence --hash-db /path/to/hash_db.csv --investigator "John Doe" --output /path/to/report.pdf
            """
        )
        self._setup_arguments()
    
    def _setup_arguments(self):
        """Setup all command line arguments"""
        self.parser.add_argument(
            '--evidence',
            required=True,
            type=str,
            help='Path to the directory to be examined'
        )
        
        self.parser.add_argument(
            '--hash-db',
            required=True,
            type=str,
            help='Path to the hash database CSV file from ILIAS'
        )
        
        self.parser.add_argument(
            '--investigator',
            required=True,
            type=str,
            help='First and last name of the investigator for the report header'
        )
        
        self.parser.add_argument(
            '--output',
            required=True,
            type=str,
            help='Target path for the PDF report'
        )
    
    def parse_args(self):
        """Parse and validate arguments"""
        args = self.parser.parse_args()
        
        # Validate arguments
        self._validate_evidence_path(args.evidence)
        self._validate_hash_db_path(args.hash_db)
        self._validate_investigator_name(args.investigator)
        self._validate_output_path(args.output)
        
        return args
    
    def _validate_evidence_path(self, evidence_path):
        """Validate evidence directory exists and is accessible"""
        if not os.path.exists(evidence_path):
            self._error(f"Evidence directory does not exist: {evidence_path}")
        
        if not os.path.isdir(evidence_path):
            self._error(f"Evidence path is not a directory: {evidence_path}")
        
        if not os.access(evidence_path, os.R_OK):
            self._error(f"Evidence directory is not readable: {evidence_path}")
    
    def _validate_hash_db_path(self, hash_db_path):
        """Validate hash database file exists and is accessible"""
        if not os.path.exists(hash_db_path):
            self._error(f"Hash database file does not exist: {hash_db_path}")
        
        if not os.path.isfile(hash_db_path):
            self._error(f"Hash database path is not a file: {hash_db_path}")
        
        if not os.access(hash_db_path, os.R_OK):
            self._error(f"Hash database file is not readable: {hash_db_path}")
        
        if not hash_db_path.lower().endswith('.csv'):
            self._error(f"Hash database file must be a CSV file: {hash_db_path}")
    
    def _validate_investigator_name(self, investigator):
        """Validate investigator name is not empty"""
        if not investigator.strip():
            self._error("Investigator name cannot be empty")
        
        if len(investigator.strip()) < 2:
            self._error("Investigator name must be at least 2 characters long")
    
    def _validate_output_path(self, output_path):
        """Validate output path is valid and directory is writable"""
        output_dir = os.path.dirname(output_path)
        
        # If no directory specified, use current directory
        if not output_dir:
            output_dir = '.'
        
        if not os.path.exists(output_dir):
            self._error(f"Output directory does not exist: {output_dir}")
        
        if not os.access(output_dir, os.W_OK):
            self._error(f"Output directory is not writable: {output_dir}")
        
        if not output_path.lower().endswith('.pdf'):
            self._error(f"Output file must be a PDF file: {output_path}")
    
    def _error(self, message):
        """Print error message and exit"""
        print(f"Error: {message}", file=sys.stderr)
        print("\nUse --help for usage information.", file=sys.stderr)
        sys.exit(1)


def parse_arguments():
    """Convenience function to parse arguments"""
    parser = ArgumentParser()
    return parser.parse_args()
