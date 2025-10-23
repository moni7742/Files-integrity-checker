import os
import time
import sys
import hashlib
import psutil

# Initialize process for memory monitoring
process = psutil.Process(os.getpid())

# Memory threshold (in MB)
MEMORY_THRESHOLD_MB = 300

# ANSI color codes
COLOR_OK = "\033[92m"       # Green
COLOR_WARNING = "\033[93m"  # Yellow
COLOR_MODIFIED = "\033[91m" # Red
COLOR_RESET = "\033[0m"

# Calculate MD5 hash for a file
def md5(fname):
    hash_md5 = hashlib.md5()
    try:
        with open(fname, "rb") as f:
            chunk_size = 4096
            while chunk := f.read(chunk_size):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except PermissionError:
        print(f"{COLOR_WARNING}Permission denied for file {fname}{COLOR_RESET}", flush=True)
    except FileNotFoundError:
        print(f"{COLOR_WARNING}File not found: {fname}{COLOR_RESET}", flush=True)
    except IOError as e:
        print(f"{COLOR_WARNING}I/O error({e.errno}) for file {fname}: {e.strerror}{COLOR_RESET}", flush=True)
    except Exception as e:
        print(f"{COLOR_WARNING}Error processing file {fname}: {e}{COLOR_RESET}", flush=True)
    return None

# Get current memory usage of the script
def get_memory_usage():
    memory_info = process.memory_info()
    memory_used_mb = memory_info.rss / 1024 / 1024
    return memory_used_mb

# Walk through a directory and check files against known hashes
def walk_and_check_hashes(directory, hash_file_path):
    # Load hash file into dict: filename -> hash
    hash_dict = {}
    files_processed = 0
    found_ok = False
    found_modified = False
    found_unknown = False

    print(f"Initial memory usage: {get_memory_usage():.2f} MB")
    start_time = time.time()

    try:
        with open(hash_file_path, 'r') as f:
            for line in f:
                parts = line.strip().split(maxsplit=1)
                if len(parts) == 2:
                    hash_val, filename = parts
                    hash_dict[filename] = hash_val
    except Exception as e:
        print(f"{COLOR_WARNING}Error loading hash file: {e}{COLOR_RESET}", flush=True)
        return

    total_files = sum(len(files) for _, _, files in os.walk(directory))
    print(f"Total files to be scanned: {total_files}")

    for root, dirs, files in os.walk(directory):
        for name in files:
            file_path = os.path.join(root, name)
            current_usage = get_memory_usage()
            if current_usage > MEMORY_THRESHOLD_MB:
                print(f"{COLOR_WARNING}\nWarning: High memory usage detected - {current_usage:.2f} MB{COLOR_RESET}")

            file_hash = md5(file_path)
            if file_hash is None:
                continue

            # Determine relative filename for hash comparison
            relative_name = name

            if relative_name in hash_dict:
                if file_hash == hash_dict[relative_name]:
                    print(f"{COLOR_OK}[OK] {file_path}{COLOR_RESET}", flush=True)
                    found_ok = True
                else:
                    print(f"{COLOR_MODIFIED}[MODIFIED] {file_path} — hash mismatch!{COLOR_RESET}", flush=True)
                    found_modified = True
            else:
                print(f"{COLOR_WARNING}[WARNING] {file_path} not in valid list{COLOR_RESET}", flush=True)
                found_unknown = True

            files_processed += 1
            if files_processed % 10 == 0:
                print(f"\rProcessed {files_processed} files...", flush=True)

    elapsed_time = time.time() - start_time
    print(f"\nFinished processing. Total files processed: {files_processed}")
    print(f"Number of hashes used for comparison: {len(hash_dict)}")
    print(f"Time taken: {elapsed_time:.2f} seconds")

    if not found_ok:
        print(f"{COLOR_WARNING}No OK files found.{COLOR_RESET}")
    if not found_modified and not found_unknown:
        print(f"{COLOR_OK}All files matched the hash list.{COLOR_RESET}")

# Main entry point
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python file_integrity_checker.py <directory_or_file_to_scan> <hash_file_path>")
        sys.exit(1)

    path_to_scan = sys.argv[1]
    hash_file_path = sys.argv[2]

    # Single file support
    if os.path.isfile(path_to_scan):
        if not os.path.exists(path_to_scan):
            print(f"{COLOR_WARNING}File not found: {path_to_scan}{COLOR_RESET}")
        else:
            print(f"Scanning single file: {path_to_scan}")
            file_hash = md5(path_to_scan)
            if file_hash:
                try:
                    hash_dict = {}
                    with open(hash_file_path, 'r') as f:
                        for line in f:
                            parts = line.strip().split(maxsplit=1)
                            if len(parts) == 2:
                                hash_val, filename = parts
                                hash_dict[filename] = hash_val
                except Exception as e:
                    print(f"{COLOR_WARNING}Error loading hash file: {e}{COLOR_RESET}", flush=True)
                    sys.exit(1)

                relative_name = os.path.basename(path_to_scan)
                if relative_name in hash_dict:
                    if file_hash == hash_dict[relative_name]:
                        print(f"{COLOR_OK}[OK] {path_to_scan}{COLOR_RESET}")
                    else:
                        print(f"{COLOR_MODIFIED}[MODIFIED] {path_to_scan} — hash mismatch!{COLOR_RESET}")
                else:
                    print(f"{COLOR_WARNING}[WARNING] {path_to_scan} not in valid list{COLOR_RESET}")
    elif os.path.isdir(path_to_scan):
        walk_and_check_hashes(path_to_scan, hash_file_path)
    else:
        print(f"{COLOR_WARNING}Invalid path: {path_to_scan}{COLOR_RESET}")
