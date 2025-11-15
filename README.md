# HashHound

```
 __    __                      __              __    __                                      __ 
|  \  |  \                    |  \            |  \  |  \                                    |  \
| $$  | $$  ______    _______ | $$____        | $$  | $$  ______   __    __  _______    ____| $$
| $$__| $$ |      \  /       \| $$    \       | $$__| $$ /      \ |  \  |  \|       \  /      $$
| $$    $$  \$$$$$$\|  $$$$$$$| $$$$$$$\      | $$    $$|  $$$$$$\| $$  | $$| $$$$$$$\|  $$$$$$$
| $$$$$$$$ /      $$ \$$    \ | $$  | $$      | $$$$$$$$| $$  | $$| $$  | $$| $$  | $$| $$  | $$
| $$  | $$|  $$$$$$$ _\$$$$$$\| $$  | $$      | $$  | $$| $$__/ $$| $$__/ $$| $$  | $$| $$__| $$
| $$  | $$ \$$    $$|       $$| $$  | $$      | $$  | $$ \$$    $$ \$$    $$| $$  | $$ \$$    $$
 \$$   \$$  \$$$$$$$ \$$$$$$$  \$$   \$$       \$$   \$$  \$$$$$$   \$$$$$$  \$$   \$$  \$$$$$$$
                                                                                                   
                          Automated Forensic Image Scanner
                                     Version 1.0
                             Developed by Jonas Sasowski
```

## Overview

**HashHound** is a professional digital forensic analysis tool designed for investigating disk images by comparing file hashes against a reference database. It automates the process of identifying known files within evidence images and generates comprehensive forensic reports suitable for legal proceedings.

The tool is particularly useful for:
- Digital forensic investigations
- Evidence analysis in legal cases
- Identifying known files in disk images
- Generating professional documentation for court proceedings

## Features

- **Automated Hash Analysis**: Searches disk images for files matching known hash values
- **Multiple Hash Algorithms**: Supports SHA-256, SHA-1, and MD5 hash comparison
- **Partition Support**: Analyzes both single filesystems and multi-partition disk images
- **Comprehensive Reporting**: Generates professional PDF reports in German (suitable for legal proceedings)
- **Detailed Metadata Extraction**: Captures file timestamps, sizes, and paths
- **Real-time Progress Monitoring**: Visual feedback during analysis with statistics
- **TSK Integration**: Uses The Sleuth Kit (pytsk3) for robust filesystem analysis
- **Debug Mode**: Verbose logging for troubleshooting and detailed analysis

## Prerequisites

Before using HashHound, ensure you have the following installed:

- **Python 3.12+**
- **Required Python packages**:
  - `pytsk3` - The Sleuth Kit Python bindings for filesystem analysis
  - `sqlalchemy` - Database operations for hash database management
  - `reportlab` - PDF report generation
  - `argparse` - Command-line argument parsing (built-in)

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Cliiive/HashHound.git
   cd HashHound
   ```

2. **Install dependencies**:
   ```bash
   pip install pytsk3 sqlalchemy reportlab
   ```

   Or if you have a requirements file:
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation**:
   ```bash
   python src/main.py --help
   ```

## Usage

### Basic Command Structure

```bash
python src/main.py --evidence <path> --hash-db <path> --investigator "<name>" --output <path> [--debug]
```

### Command-Line Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--evidence` | Yes | Path to the directory or disk image to be examined |
| `--hash-db` | Yes | Path to the hash database CSV file (VIC Hash Database format) |
| `--investigator` | Yes | First and last name of the investigator (for report header) |
| `--output` | Yes | Target path for the PDF report (must end with .pdf) |
| `--debug` | No | Enable debug mode for verbose output |

### Example Usage

**Basic forensic analysis**:
```bash
python src/main.py \
  --evidence /path/to/evidence.dd \
  --hash-db /path/to/vic_hashes.csv \
  --investigator "John Doe" \
  --output /path/to/reports/analysis_report.pdf
```

**With debug logging**:
```bash
python src/main.py \
  --evidence /mnt/evidence/disk_image.dd \
  --hash-db ./databases/hashes.db \
  --investigator "Jane Smith" \
  --output ./output/forensic_report.pdf \
  --debug
```

**Analyzing a directory**:
```bash
python src/main.py \
  --evidence /path/to/directory \
  --hash-db ./hashes.db \
  --investigator "Detective Brown" \
  --output ./report_$(date +%Y%m%d).pdf
```

## Workflow

1. **Preparation**: Prepare your evidence disk image and hash database
2. **Launch**: Run HashHound with appropriate arguments
3. **Review Parameters**: The tool displays your parameters and waits for confirmation
4. **Analysis**: HashHound scans the evidence image comparing file hashes
5. **Progress Monitoring**: Real-time statistics show files searched and matches found
6. **Report Generation**: A comprehensive PDF report is automatically generated
7. **Review**: Examine the generated forensic report

### Output

HashHound generates a professional forensic report in German that includes:

- **Report Header**: Investigator name, date, evidence path, case information
- **Executive Summary**: Overview of findings and methodology
- **Methodology Section**: Detailed description of analysis procedures
- **Findings Table**: Summary table of all matching files
- **Detailed Results**: Complete metadata for each finding including:
  - File name and path
  - File size
  - SHA-256 hash value
  - Created, modified, and accessed timestamps
  - Partition offset information
- **Technical Details**: Information about the analysis process and tools used
- **Signature Section**: Space for investigator certification

### Sample Console Output

```
Starting forensic analysis...

|| START TIME || ELAPSED    || FOUND FILES     || SEARCHED FILES  ||
||____________||____________||_________________||_________________||
||  14:23:45  ||  00:02:15  ||       3         ||      1,247      ||

Analysis completed. Found 3 matching files.
Forensic report generated successfully: /path/to/report.pdf
```

## Hash Database Format

HashHound expects a SQLite database with a table named `VIC_HASHES` containing:

- Table: `VIC_HASHES`
- Column: `hash_value` (TEXT, PRIMARY KEY)

The database should contain hash values (SHA-256, SHA-1, or MD5) of known files to search for.

## Project Structure

```
HashHound/
├── src/
│   ├── main.py                 # Main entry point
│   └── core/
│       ├── arg_parser.py       # Command-line argument parsing
│       ├── ascii_art.py        # Banner display
│       ├── database.py         # Database operations
│       ├── image_search.py     # Forensic search logic
│       ├── logger.py           # Logging functionality
│       ├── models.py           # Data models
│       └── pdf_generator.py    # PDF report generation
├── LICENSE                     # MIT License
└── README.md                   # This file
```

## Technical Details

### Hash Comparison
- HashHound computes SHA-256, SHA-1, and MD5 hashes for each file
- Compares computed hashes against the reference database
- Uses set intersection for efficient matching

### Filesystem Analysis
- Uses pytsk3 (The Sleuth Kit) for filesystem traversal
- Supports multiple partitions and partition tables
- Handles both raw filesystems and disk images with partition tables
- Extracts comprehensive file metadata including timestamps

### Report Generation
- Uses ReportLab for professional PDF generation
- Follows German legal standards for digital evidence documentation
- Includes all necessary information for court proceedings
- Automatically formats dates, file sizes, and technical details

## Limitations

- Hash database must be in the specified SQLite format
- Large disk images may take considerable time to process
- Some filesystem types may not be fully supported by pytsk3
- Reports are generated in German language only

## Security Considerations

- HashHound operates in read-only mode on evidence images
- No modifications are made to original evidence
- All operations are logged for audit trails
- Hash values ensure integrity of findings

## Troubleshooting

**Error: "Evidence directory does not exist"**
- Verify the path to your evidence file or directory
- Ensure you have read permissions

**Error: "Hash database file does not exist"**
- Check that the database path is correct
- Verify the database file exists and is readable

**Error: "Failed to connect to database"**
- Ensure the database is in SQLite format
- Check that the `VIC_HASHES` table exists

**No matches found**
- Verify that the hash database contains the hashes you're looking for
- Check that hash values in the database are lowercase
- Ensure the evidence image is accessible and not corrupted

## Contributing

Contributions to HashHound are welcome! Please ensure that:
- Code follows existing style conventions
- Changes are well-documented
- Forensic integrity principles are maintained

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License
Copyright (c) 2025 Jonas Sasowski
```

## Author

**Jonas Sasowski**

## Acknowledgments

- The Sleuth Kit (TSK) project for pytsk3
- ReportLab for PDF generation capabilities
- SQLAlchemy for database operations

## Version History

- **1.0** - Initial release
  - Core hash analysis functionality
  - PDF report generation
  - Multi-partition support
  - Real-time progress monitoring

---

**Note**: This tool is designed for legitimate forensic investigations and legal proceedings. Users are responsible for ensuring compliance with applicable laws and regulations regarding digital evidence collection and analysis.
