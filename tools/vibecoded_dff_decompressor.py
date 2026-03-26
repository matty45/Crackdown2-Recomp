import zlib
import sys
import os

def decompress_dff(input_file, output_file=None):
    """
    Decompress a .dff file that uses zlib compression as seen in the RenderWare stream handling.
    
    Args:
        input_file (str): Path to the compressed .dff file
        output_file (str): Path for the decompressed output (optional)
    
    Returns:
        bytes: The decompressed data
    """
    if output_file is None:
        output_file = os.path.splitext(input_file)[0] + '_decompressed.dff'
    
    try:
        # Read the compressed file
        with open(input_file, 'rb') as f:
            compressed_data = f.read()
        
        print(f"Read {len(compressed_data)} bytes from {input_file}")
        
        # Try to decompress with zlib
        # Based on our analysis, this uses standard zlib with windowBits=15
        # (which is the default for decompress)
        try:
            decompressed_data = zlib.decompress(compressed_data)
            print(f"Decompressed to {len(decompressed_data)} bytes")
        except zlib.error as e:
            print(f"Standard zlib decompression failed: {e}")
            # Try with raw deflate format (without zlib headers)
            try:
                decompressed_data = zlib.decompress(compressed_data, -15)  # raw deflate
                print(f"Decompressed (raw deflate) to {len(decompressed_data)} bytes")
            except zlib.error as e2:
                print(f"Raw deflate decompression also failed: {e2}")
                # Try with gzip format
                try:
                    decompressed_data = zlib.decompress(compressed_data, 15 + 32)  # gzip
                    print(f"Decompressed (gzip) to {len(decompressed_data)} bytes")
                except zlib.error as e3:
                    print(f"Gzip decompression also failed: {e3}")
                    raise
        
        # Write the decompressed data
        with open(output_file, 'wb') as f:
            f.write(decompressed_data)
        
        print(f"Decompressed data written to {output_file}")
        return decompressed_data
        
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error during decompression: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print("Usage: python decompress_dff.py <input_file.dff> [output_file]")
        print("Example: python decompress_dff.py model.dff model_decompressed.dff")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    decompress_dff(input_file, output_file)

if __name__ == "__main__":
    main()