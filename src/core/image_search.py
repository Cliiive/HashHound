import pytsk3
from pathlib import Path
import time
import datetime
from core.logger import get_logger
from core.models import Finding
from typing import List
from concurrent.futures import ThreadPoolExecutor
import sys

FOUND_FILES = 0
SEARCHED_FILES = 0
STOP_LOGGING = False

def run_search_with_logging(image_path, hashes):
    import time
    global STOP_LOGGING
    start_time = time.time()
    STOP_LOGGING = False

    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(search_image_for_hashes, image_path, hashes)
        f2 = executor.submit(log_stats, start_time)

        result = f1.result()  # blocks until done
        STOP_LOGGING = True   # signal logger thread to stop
        f2.result()           # wait for it to finish cleanly
        return result

def search_image_for_hashes(image_path, hashes) -> List[Finding]:
    """
    Search a disk image for specific hash values.
    
    Args:
        image_path (str): Path to the disk image file.
        hashes (set): Set of hash values to search for.
        
    Returns:
        List[Finding]: List of findings containing matched files and their metadata.
    """
    logger = get_logger()
    all_findings = []
    
    try:
        # Open the disk image
        img = pytsk3.Img_Info(image_path)
        
        # Try to get volume/partition information
        try:
            volume = pytsk3.Volume_Info(img)
            # Iterate through partitions
            for partition in volume:
               
                logger.info(f"Searching partition at offset {partition.start}")
                try:
                    # Create filesystem for this partition
                    fs = pytsk3.FS_Info(img, offset=partition.start * volume.info.block_size)
                    partition_findings = search_filesystem(fs, hashes, partition.start)
                    all_findings.extend(partition_findings)
                except Exception as e:
                    logger.error(f"Could not access filesystem on partition at offset {partition.start}: {e}")
        except:
            # No partition table found, try as single filesystem
            logger.info("No partition table found, treating as single filesystem")
            fs = pytsk3.FS_Info(img)
            partition_findings = search_filesystem(fs, hashes)
            all_findings.extend(partition_findings)
            
    except Exception as e:
        logger.error(f"Error opening image {image_path}: {e}")
    
    return all_findings

def walk_fs(fs, path="/"):
    try:
        directory = fs.open_dir(path)
    except IOError:
        return
    for entry in directory:
        if not hasattr(entry, "info") or not entry.info.name:
            continue
        name = entry.info.name.name.decode(errors="ignore")
        if name in [".", ".."] or name.startswith("$"):
            continue
        full_path = "/".join([path.strip("/"), name]).replace("//", "/")
        if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            yield from walk_fs(fs, "/" + full_path)
        else:
            yield "/" + full_path

def extract_file_metadata(file_obj, file_path):
    """Extract metadata from a file object."""
    size = file_obj.info.meta.size if file_obj.info.meta else 0
    file_name = file_path.split('/')[-1] if '/' in file_path else file_path
    
    # Extract timestamps if available
    created_time = None
    modified_time = None
    accessed_time = None
    
    if file_obj.info.meta:
        if hasattr(file_obj.info.meta, 'crtime') and file_obj.info.meta.crtime:
            created_time = datetime.datetime.fromtimestamp(file_obj.info.meta.crtime)
        if hasattr(file_obj.info.meta, 'mtime') and file_obj.info.meta.mtime:
            modified_time = datetime.datetime.fromtimestamp(file_obj.info.meta.mtime)
        if hasattr(file_obj.info.meta, 'atime') and file_obj.info.meta.atime:
            accessed_time = datetime.datetime.fromtimestamp(file_obj.info.meta.atime)
    
    return size, file_name, created_time, modified_time, accessed_time

def compute_file_hash(file_obj, size):
    """Compute SHA256 hash of file data."""
    import hashlib
    data = file_obj.read_random(0, size) if size else b""
    return hashlib.sha256(data).hexdigest()

def create_finding(file_hash, file_path, size, file_name, partition_offset, 
                  created_time, modified_time, accessed_time):
    """Create a Finding object with the provided metadata."""
    return Finding(
        hash_value=file_hash,
        file_path=file_path,
        file_size=size,
        file_name=file_name,
        partition_offset=partition_offset,
        created_time=created_time,
        modified_time=modified_time,
        accessed_time=accessed_time
    )

def process_single_file(file_path, fs, hashes, partition_offset, logger):
    """Process a single file and return a Finding if hash matches."""
    try:
        logger.debug(f"Processing file: {file_path}")
        file_obj = fs.open(file_path)
        
        # Extract metadata
        size, file_name, created_time, modified_time, accessed_time = extract_file_metadata(file_obj, file_path)
        
        # Compute hash
        file_hash = compute_file_hash(file_obj, size)
        
        # Check if hash matches
        if file_hash in hashes:
            logger.debug(f"Found matching file for hash << {file_hash[0:5]}...{file_hash[-6:-1]} >> at {file_path}")
            return create_finding(file_hash, file_path, size, file_name, partition_offset,
                                created_time, modified_time, accessed_time)
        
        return None
        
    except Exception as e:
        logger.warning(f"Error processing file {file_path}: {e}")
        return None

def report_progress(processed_files, matches_found, start_time, last_progress_time, 
                   progress_interval, logger):
    """Report search progress if enough time has elapsed."""
    current_time = time.time()
    if current_time - last_progress_time >= progress_interval:
        elapsed_time = current_time - start_time
        files_per_second = processed_files / elapsed_time
        logger.debug(f"Search progress: {processed_files} files processed, {matches_found} matches found ({files_per_second:.1f} files/sec)")
        return current_time
    return last_progress_time

def search_filesystem(fs, hashes, partition_offset=None) -> List[Finding]:
    """Search a filesystem for matching hashes and return findings."""
    global FOUND_FILES, SEARCHED_FILES
    logger = get_logger()
    findings = []
    
    processed_files = 0
    matches_found = 0
    last_progress_time = time.time()
    progress_interval = 1.0  # Report progress every 1 second
    start_time = time.time()
    
    logger.info("Starting filesystem search...")
    
    for file_path in walk_fs(fs):
        # Process the file
        finding = process_single_file(file_path, fs, hashes, partition_offset, logger)
        
        if finding:
            findings.append(finding)
            matches_found += 1
        
        processed_files += 1

        SEARCHED_FILES = processed_files
        FOUND_FILES = matches_found
        
        # Report progress periodically
        last_progress_time = report_progress(processed_files, matches_found, start_time, 
                                           last_progress_time, progress_interval, logger)
    
    # Final report
    total_time = time.time() - start_time
    avg_rate = processed_files / total_time if total_time > 0 else 0
    print("\n")
    logger.info(f"Search completed: {processed_files} files processed, {matches_found} matches found in {total_time:.1f}s (avg: {avg_rate:.1f} files/sec)")
    
    return findings

#### LOGGING ####

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"

def format_number(n):
    return f"{n:,}"

def log_stats(start_time):
    global FOUND_FILES, SEARCHED_FILES, STOP_LOGGING
    time.sleep(0.5)
    
    # Print table header once
    header = (
        f"{BOLD}{CYAN}|| {'START TIME':^10} || {'ELAPSED':^10} || "
        f"{'FOUND FILES':^15} || {'SEARCHED FILES':^15} ||{RESET}"
    )
    separator = f"{BOLD}{CYAN}||{'_'*12}||{'_'*12}||{'_'*17}||{'_'*17}||{RESET}"
    
    print("\n" + header)
    print(separator)
    
    while not STOP_LOGGING:
        elapsed = time.time() - start_time
        elapsed_str = f"{int(elapsed//3600):02}:{int((elapsed%3600)//60):02}:{int(elapsed%60):02}"
        
        line = (
            f"{BOLD}{CYAN}||{RESET} "
            f"{YELLOW}{time.strftime('%H:%M:%S', time.localtime(start_time)):^10}{RESET} || "
            f"{MAGENTA}{elapsed_str:^10}{RESET} || "
            f"{GREEN}{format_number(FOUND_FILES):^15}{RESET} || "
            f"{RED}{format_number(SEARCHED_FILES):^15}{RESET} ||"
        )
        
        # Overwrite previous line
        sys.stdout.write(f"\r{line}")
        sys.stdout.flush()
        time.sleep(0.2)
    print("\n")