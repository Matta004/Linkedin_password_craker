import hashlib  # For computing SHA-1 hashes
from tqdm import tqdm  # For displaying progress bars
import time  # For tracking script execution time

def load_file(file_path):
    """
    Load the contents of a file into a set.

    Args:
        file_path (str): Path to the file.

    Returns:
        set: A set containing the stripped lines of the file.
    """
    try:
        # Open the file and read all lines, stripping whitespace
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            return set(line.strip() for line in file)
    except FileNotFoundError:
        # Handle case where the file does not exist
        print(f"Error: File not found at {file_path}")
        return set()

def hash_wordlist(wordlist_path, output_path):
    """
    Hash each word in a wordlist using SHA-1 and save the hashes to a file.

    Args:
        wordlist_path (str): Path to the wordlist file.
        output_path (str): Path to save the output file containing hashes.
    """
    try:
        # Open the wordlist for reading and the output file for writing
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as wordlist, \
             open(output_path, 'w') as output_file:
            
            # Count total lines in the wordlist for the progress bar
            total_lines = sum(1 for _ in open(wordlist_path, 'r', encoding='utf-8', errors='ignore'))
            
            print(f"Hashing words from {wordlist_path} and saving hashes to {output_path}...")
            
            # Iterate through each word in the wordlist
            for word in tqdm(wordlist, total=total_lines, desc="Hashing Progress", unit="word", ncols=80):
                word = word.strip()  # Remove any extra whitespace
                hashed_word = hashlib.sha1(word.encode('utf-8')).hexdigest()  # Compute the SHA-1 hash
                output_file.write(f"{hashed_word}\n")  # Save the hash to the output file
        
        print(f"Hashing complete. Results saved in {output_path}")
    except FileNotFoundError:
        # Handle case where the wordlist file is not found
        print(f"Error: File {wordlist_path} not found.")

def compare_and_count(file1, file2, output_file):
    """
    Compare two sets of data and count the number of matches.

    Args:
        file1 (str): Path to the first file.
        file2 (str): Path to the second file.
        output_file (str): Path to save the matched results.
    """
    # Load both files into sets
    set1 = load_file(file1)
    set2 = load_file(file2)

    matches = set()  # Initialize an empty set to store matches
    # Iterate through the first set with a progress bar
    for item in tqdm(set1, desc="Comparing Progress", unit="hash", ncols=80):
        if item in set2:  # Check if the item exists in the second set
            matches.add(item)  # Add to matches if a match is found

    # Write all matches to the output file
    with open(output_file, "w") as output:
        for match in matches:
            output.write(f"{match}\n")
    
    print(f"\nNumber of similarities found: {len(matches)}")
    print(f"Similarities saved to '{output_file}'.")

def unhash_similarities(similarities_file, wordlist_file, output_file):
    """
    Match hashes to plaintext passwords from the wordlist.

    Args:
        similarities_file (str): Path to the file containing matched hashes.
        wordlist_file (str): Path to the wordlist file.
        output_file (str): Path to save unhashed results.

    Returns:
        dict: A dictionary mapping hashes to their plaintext passwords.
    """
    similarities = load_file(similarities_file)  # Load matched hashes
    unhashed = {}  # Initialize a dictionary to store unhashed results

    print(f"Attempting to unhash {len(similarities)} hashes using the wordlist...")

    try:
        # Open the wordlist for reading and the output file for writing
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as wordlist, \
             open(output_file, 'w') as output:
            
            # Count total lines in the wordlist for the progress bar
            total_lines = sum(1 for _ in open(wordlist_file, 'r', encoding='utf-8', errors='ignore'))
            
            # Iterate through the wordlist
            for word in tqdm(wordlist, total=total_lines, desc="Unhashing Progress", unit="word", ncols=80):
                word = word.strip()  # Remove extra whitespace
                hashed_word = hashlib.sha1(word.encode('utf-8')).hexdigest()  # Compute the SHA-1 hash
                if hashed_word in similarities:  # Check if the hash matches
                    unhashed[hashed_word] = word  # Map the hash to the plaintext password
                    output.write(f"{hashed_word} -> {word}\n")  # Save to output file
        
        print(f"Unhashing complete. Results saved in {output_file}.")
        return unhashed  # Return the mapping of hashes to plaintext
    except FileNotFoundError:
        # Handle case where the wordlist file is not found
        print(f"Error: File {wordlist_file} not found.")
        return {}

def main():
    """
    Main function to execute the script steps in sequence.
    """
    start_time = time.time()  # Record the start time

    # Define file paths
    wordlist_file = "rockyou.txt"  # Input wordlist file
    hashed_output_file = "rockyou_hashed_sha1.txt"  # Output file for hashed wordlist
    file1 = hashed_output_file  # First file to compare (hashed wordlist)
    file2 = "LinkedIn_HalfMillionHashes.txt"  # Second file to compare (target hashes)
    similarities_output_file = "similarities.txt"  # Output file for matched hashes
    unhashed_output_file = "unhashed_similarities.txt"  # Output file for unhashed results

    # Step 1: Hash the wordlist
    print("Step 1: Hashing the wordlist...")
    hash_wordlist(wordlist_file, hashed_output_file)

    # Step 2: Compare hashed wordlist with the target hash file
    print("\nStep 2: Comparing the hashed wordlist with the target hash file...")
    compare_and_count(file1, file2, similarities_output_file)

    # Step 3: Unhash matched hashes to find plaintext passwords
    print("\nStep 3: Unhashing matched hashes to find plaintext passwords...")
    unhashed = unhash_similarities(similarities_output_file, wordlist_file, unhashed_output_file)

    # Calculate and print total runtime
    end_time = time.time()
    total_time = end_time - start_time
    print(f"\nTotal runtime: {total_time:.2f} seconds")

    # Display the number of cracked passwords and top 3 passwords
    cracked_count = len(unhashed)
    print(f"\nHow many passwords did you manage to crack using the rockyou.txt file? {cracked_count}")
    
    if cracked_count > 0:
        top_words = list(unhashed.values())[:3]  # Extract the top 3 passwords
        print(f"The top 3 passwords on your list are: {', '.join(top_words)}")

# Run the main function if the script is executed directly
if __name__ == "__main__":
    main()
