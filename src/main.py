from core.arg_parser import parse_arguments
from core.database import get_hashes
from core.logger import get_logger
from core.image_search import search_image_for_hashes
from core.pdf_generator import generate_forensic_report
import sys
import os

def print_params(evidence_path, hash_db_path, investigator_name, output_path, logger):
    logger.info("Parsed Command Line Arguments:")
    logger.info(f"Evidence Path   : {evidence_path}")
    logger.info(f"Hash DB Path    : {hash_db_path}")
    logger.info(f"Investigator    : {investigator_name}")
    logger.info(f"Output Path     : {output_path}")

def main():
    # Parse command line arguments
    args = parse_arguments()
    
    # Access parsed arguments
    evidence_path = args.evidence
    hash_db_path = args.hash_db
    investigator_name = args.investigator
    output_path = args.output
    debug_mode = args.debug
    
    # Get singleton logger and set debug mode
    logger = get_logger()
    logger.set_debug_mode(debug_mode)
        
    # Print parsed arguments for verification
    print_params(evidence_path, hash_db_path, investigator_name, output_path, logger)
    
    try:
        hashes = get_hashes()
        logger.debug(f"Retrieved {len(hashes)} records from VIC_HASHES table.")
        for record in hashes:
            logger.debug(f"Hash : {record}")
    except Exception as e:
        logger.error(f"Failed to retrieve hashes from database: {e}")
        return 1

    # Perform the forensic search
    logger.info("Starting forensic analysis...")
    findings = search_image_for_hashes(evidence_path, hashes)
    
    logger.info(f"Analysis completed. Found {len(findings)} matching files.")
    
    # Generate the forensic report
    try:
        # Ensure output path has .pdf extension
        if not output_path.lower().endswith('.pdf'):
            output_path = output_path + '.pdf'
        
        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Generate PDF report
        report_path = generate_forensic_report(
            findings=findings,
            investigator_name=investigator_name,
            evidence_path=evidence_path,
            output_path=output_path
        )
        
        logger.info(f"Forensic report generated successfully: {report_path}")
        
        # Print summary to console
        if findings:
            logger.info("\n=== ANALYSIS SUMMARY ===")
            for i, finding in enumerate(findings, 1):
                logger.info(f"{i}. {finding.file_name} ({finding.file_size:,} bytes)")
                logger.info(f"   Hash: {finding.hash_value}")
                logger.info(f"   Path: {finding.file_path}")
        else:
            logger.info("No matching files found in the evidence image.")
            
    except Exception as e:
        logger.error(f"Failed to generate forensic report: {e}")
        return 1
        
    return 0
    

if __name__ == "__main__":
    main()