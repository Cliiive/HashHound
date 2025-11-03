import pytsk3
from pathlib import Path
import time
import datetime
from core.logger import get_logger
from core.models import Finding
from typing import List

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

def search_filesystem(fs, hashes, partition_offset=None) -> List[Finding]:
    logger = get_logger()
    findings = []
    
    processed_files = 0
    matches_found = 0
    last_progress_time = time.time()
    progress_interval = 1.0  # Report progress every 1 second
    start_time = time.time()
    
    logger.info("Starting filesystem search...")
    
    for file_path in walk_fs(fs):
        try:
            logger.debug(f"Processing file: {file_path}")
            file_obj = fs.open(file_path)
            
            # Get file metadata
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
            
            # Read file data and compute hash
            data = file_obj.read_random(0, size) if size else b""
            import hashlib
            file_hash = hashlib.sha256(data).hexdigest()
            
            if file_hash in hashes:
                matches_found += 1
                
                # Create Finding object
                finding = Finding(
                    hash_value=file_hash,
                    file_path=file_path,
                    file_size=size,
                    file_name=file_name,
                    partition_offset=partition_offset,
                    created_time=created_time,
                    modified_time=modified_time,
                    accessed_time=accessed_time
                )
                
                findings.append(finding)
                logger.info(f"Found matching file for hash << {file_hash[0:5]}...{file_hash[-6:-1]} >> at {file_path}")
                
        except Exception as e:
            logger.warning(f"Error processing file {file_path}: {e}")
        
        processed_files += 1
        
        # Report progress periodically with rate information
        current_time = time.time()
        if current_time - last_progress_time >= progress_interval:
            elapsed_time = current_time - start_time
            files_per_second = processed_files / elapsed_time
            logger.info(f"Search progress: {processed_files} files processed, {matches_found} matches found ({files_per_second:.1f} files/sec)")
            last_progress_time = current_time
    
    # Final report
    total_time = time.time() - start_time
    avg_rate = processed_files / total_time if total_time > 0 else 0
    logger.info(f"Search completed: {processed_files} files processed, {matches_found} matches found in {total_time:.1f}s (avg: {avg_rate:.1f} files/sec)")
    
    return findings