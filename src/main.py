from core.arg_parser import parse_arguments


def main():
    # Parse command line arguments
    args = parse_arguments()
    
    # Access parsed arguments
    evidence_path = args.evidence
    hash_db_path = args.hash_db
    investigator_name = args.investigator
    output_path = args.output
    
    # Print parsed arguments for verification
    print(f"Evidence directory: {evidence_path}")
    print(f"Hash database: {hash_db_path}")
    print(f"Investigator: {investigator_name}")
    print(f"Output report: {output_path}")
    
    # TODO: Implement further logic here
    
    return 0
    

if __name__ == "__main__":
    main()