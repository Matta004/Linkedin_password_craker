import hashlib  # For computing SHA-1 hashes
from tqdm import tqdm  # For displaying a progress bar

def load_hashes(file_path):
    """
    Load SHA-1 hashes from the specified file.

    Args:
        file_path (str): Path to the file containing the hashes.

    Returns:
        list: A list of SHA-1 hashes as strings.
    """
    try:
        # Open the file and read all lines, stripping whitespace
        with open(file_path, 'r') as file:
            return [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        # Handle case where the file does not exist
        print(f"Error: File not found at {file_path}")
        return []

def load_wordlist(wordlist_path):
    """
    Load potential passwords from the specified wordlist.

    Args:
        wordlist_path (str): Path to the wordlist file.

    Returns:
        list: A list of potential passwords as strings.
    """
    try:
        # Open the file and read all lines, stripping whitespace
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            return [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        # Handle case where the file does not exist
        print(f"Error: Wordlist file not found at {wordlist_path}")
        return []

def crack_hashes(hashes, wordlist):
    """
    Attempt to crack the provided SHA-1 hashes using a wordlist.

    Args:
        hashes (list): List of SHA-1 hash strings to crack.
        wordlist (list): List of potential passwords to test against the hashes.

    Returns:
        int: The number of successfully cracked hashes.
    """
    cracked_count = 0  # Counter for successfully cracked hashes

    # Open output files for storing results
    with open("cracked_hashes.txt", "w") as cracked_file, open("extracted.txt", "w") as extracted_file:
        # Iterate over each word in the wordlist with a progress bar
        for word in tqdm(wordlist, desc="Cracking Progress", unit="word", ncols=80):
            # Compute the SHA-1 hash of the current word
            hashed_word = hashlib.sha1(word.encode('utf-8')).hexdigest()

            # Check if the hash matches any in the provided list
            if hashed_word in hashes:
                cracked_count += 1  # Increment cracked count
                # Write the cracked hash and corresponding word to the files
                cracked_file.write(f"{hashed_word} -> {word}\n")
                extracted_file.write(f"{word}\n")
    return cracked_count  # Return total cracked hashes

def main():
    """
    Main function to orchestrate hash cracking.
    """
    hashes_file = "LinkedIn_HalfMillionHashes.txt"  # File path for the hash list
    wordlist_file = "rockyou.txt"  # File path for the wordlist

    print("Loading hashes...")
    hashes = load_hashes(hashes_file)  # Load hashes from the file

    if not hashes:
        # Exit if no hashes were loaded
        print("No hashes loaded. Exiting.")
        return

    print("Loading wordlist...")
    wordlist = load_wordlist(wordlist_file)  # Load the wordlist from the file

    if not wordlist:
        # Exit if no wordlist was loaded
        print("No wordlist loaded. Exiting.")
        return

    print(f"Attempting to crack {len(hashes)} hashes using {len(wordlist)} words...")
    # Attempt to crack the hashes and count the total cracked
    total_cracked = crack_hashes(hashes, wordlist)

    # Print final results
    print(f"\nCracking complete. Total cracked: {total_cracked}")
    print("Results saved in 'cracked_hashes.txt' and extracted passwords saved in 'extracted.txt'.")

# Entry point of the script
if __name__ == "__main__":
    main()
