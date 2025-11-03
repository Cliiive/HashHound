from dataclasses import dataclass
from typing import Optional
import datetime

@dataclass
class Finding:
    """
    Represents a file found during hash search with its metadata.
    """
    hash_value: str
    file_path: str
    file_size: int
    file_name: str
    partition_offset: Optional[int] = None
    created_time: Optional[datetime.datetime] = None
    modified_time: Optional[datetime.datetime] = None
    accessed_time: Optional[datetime.datetime] = None
    
    def __str__(self):
        return f"Finding(hash={self.hash_value[:8]}..., path={self.file_path}, size={self.file_size})"
    
    def __repr__(self):
        return self.__str__()