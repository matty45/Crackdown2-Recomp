#!/usr/bin/env python3
"""
Crackdown 2 DFF File Parser
Based on reverse engineering of _ProcessStream_CStreamHandler_RWS__SAXPAURwStream___K_Z
and related stream processing functions in the Xbox 360 binary.

This parser handles:
1. Zlib decompression of DFF files (rwSTREAMCOMPRESSEDFILE)
2. Chunk-based RenderWare stream format with the game's specific header reading logic
3. Handler dispatch pattern for known chunk types
4. Little-endian data interpretation (PowerPC/Xbox 360 uses little-endian for chunk headers)
"""

import zlib
import struct
import sys
import os
from typing import Dict, Callable, Any
from dataclasses import dataclass


@dataclass
class RwChunkHeaderInfo:
    """RenderWare chunk header information"""
    type: int
    length: int
    version: int
    buildNum: int
    isComplex: bool = False  # We don't have the ChunkIsComplex function, so default to False


class DFFParser:
    """Parser for Crackdown 2 DFF files based on reverse-engineered stream processing"""
    
    def __init__(self):
        self.handlers: Dict[int, Callable[..., None]] = {}
        self.register_known_handlers()
        self.verbose = False
        
    def register_handler(self, chunk_type: int, func: Callable[..., None]):
        """Register a handler function for a specific chunk type"""
        self.handlers[chunk_type] = func
        
    def register_known_handlers(self):
        """Register handlers discovered through reverse engineering"""
        # Resource Manager handlers from RegisterStreamChunkHandlers
        self.register_handler(0xBADCAB01, self.handle_resource_catalogue)
        self.register_handler(0xBADCAB02, self.handle_resource_cache_global_setup)
        self.register_handler(0xBADCAB03, self.handle_resource_cache_level_setup)
        
        # MainLoop handlers
        self.register_handler(0x700, self.handle_mainloop_reset)
        self.register_handler(0x70B, self.handle_mainloop_start_system)
        self.register_handler(0x70C, self.handle_mainloop_stop_system)
        self.register_handler(0x71D, self.handle_mainloop_init)
        
        # Special chunks handled in ProcessStream
        self.register_handler(0x704, self.handle_game_database_load)  # 1796
        self.register_handler(0x705, self.handle_entity_attributes)   # 1797
        
        # Common RenderWare chunks (these would need to be discovered from other handlers)
        self.register_handler(0x00000001, self.handle_rw_string)      # rwID_STRING
        self.register_handler(0x00000002, self.handle_rw_extension)   # rwID_EXTENSION
        self.register_handler(0x0000000F, self.handle_rw_texture)     # rwID_TEXTURE
        self.register_handler(0x00000010, self.handle_rw_material)    # rwID_MATERIAL
        self.register_handler(0x00000011, self.handle_rw_matrix)      # rwID_MATRIX
        self.register_handler(0x00000012, self.handle_rw_frame)       # rwID_FRAME
        self.register_handler(0x00000013, self.handle_rw_mesh)        # rwID_MESH
        self.register_handler(0x00000014, self.handle_rw_clump)       # rwID_CLUMP
        self.register_handler(0x00000015, self.handle_rw_atomic)      # rwID_ATOMIC
        self.register_handler(0x00000016, self.handle_rw_light)       # rwID_LIGHT
        self.register_handler(0x00000017, self.handle_rw_camera)      # rwID_CAMERA
        
    def log(self, message: str):
        """Conditional logging"""
        if self.verbose:
            print(f"[DFF Parser] {message}")
            
    def parse_file(self, filepath: str) -> bool:
        """
        Parse a DFF file
        
        Args:
            filepath: Path to the .dff file
            
        Returns:
            True if parsing succeeded, False otherwise
        """
        try:
            # Step 1: Decompress the file (simulating RwStreamOpen + decompression)
            self.log(f"Reading compressed DFF file: {filepath}")
            with open(filepath, 'rb') as f:
                compressed_data = f.read()
                
            self.log(f"Read {len(compressed_data)} bytes of compressed data")
            
            # Decompress using zlib (based on InitInflatePartial -> inflateInit_)
            try:
                # The game uses zlib decompression as seen in StreamCompressedFileInitialize
                decompressed_data = zlib.decompress(compressed_data)
            except zlib.error:
                # Try raw deflate if standard fails
                try:
                    decompressed_data = zlib.decompress(compressed_data, -15)
                except zlib.error:
                    # Try gzip format
                    decompressed_data = zlib.decompress(compressed_data, 15 + 32)
                    
            self.log(f"Decompressed to {len(decompressed_data)} bytes")
            
            # Step 2: Parse chunks from decompressed data
            return self._parse_chunks(decompressed_data)
            
        except FileNotFoundError:
            print(f"Error: File '{filepath}' not found.")
            return False
        except Exception as e:
            print(f"Error parsing DFF file: {e}")
            return False
            
    def _parse_chunks(self, data: bytes) -> bool:
        """
        Parse chunks from decompressed data using the game's rwStreamReadChunkHeader logic
        
        This replicates the logic from ?ProcessStream@CStreamHandler@RWS@@SAXPAURwStream@@_K@Z
        """
        pos = 0
        chunk_count = 0
        
        self.log("Starting chunk parsing...")
        
        while pos < len(data):
            # Check if we have enough data for a header (12 bytes)
            if pos + 12 > len(data):
                self.log(f"Incomplete header at position {pos}, stopping")
                break
                
            # Read the 12-byte header as per rwStreamReadChunkHeader
            # v12[0] = type (4 bytes, little-endian)
            # v12[1] = length (4 bytes, little-endian)
            # v13 = version/buildNum combined (4 bytes, little-endian)
            type_val = struct.unpack('<I', data[pos:pos+4])[0]
            length_val = struct.unpack('<I', data[pos+4:pos+8])[0]
            v13 = struct.unpack('<I', data[pos+8:pos+12])[0]
            
            # Compute version and buildNum as per rwStreamReadChunkHeader
            if (v13 & 0xFFFF0000) != 0:
                # High 16 bits of v13 are not zero
                buildNum = v13 & 0xFFFF
                version = (((v13 >> 14) & 0x3FF00) + 196608) | ((v13 >> 16) & 0x3F)
            else:
                version = v13 << 8
                buildNum = 0
            
            header = RwChunkHeaderInfo(
                type=type_val,
                length=length_val,
                version=version,
                buildNum=buildNum
            )
            
            self.log(f"Chunk #{chunk_count}: type=0x{header.type:08X} ({header.type}), "
                    f"length={header.length}, version=0x{header.version:08X}, build=0x{header.buildNum:08X}")
            
            pos += 12  # Move past header
            
            # Validate chunk length
            if header.length < 0 or pos + header.length > len(data):
                self.log(f"Error: Invalid chunk length {header.length} at position {pos}")
                break
                
            # Extract chunk data
            chunk_data = data[pos:pos+header.length]
            
            # Step 3: Dispatch to handler (replicates ProcessStream logic)
            handler = self.handlers.get(header.type)
            if handler:
                try:
                    self.log(f"Calling handler for chunk 0x{header.type:08X}")
                    handler(header, chunk_data)
                except Exception as e:
                    self.log(f"Error in handler for chunk 0x{header.type:08X}: {e}")
                    # Continue parsing other chunks
            else:
                self.log(f"No handler for chunk 0x{header.type:08X} ({header.type}), skipping {header.length} bytes")
                
            pos += header.length
            chunk_count += 1
            
        self.log(f"Finished parsing. Processed {chunk_count} chunks.")
        return True
        
    # Handler implementations based on reverse-engineered functions
    
    def handle_resource_catalogue(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle 0xBADCAB01 - ResourceManager::cResourceCatalogue::LoadResourceCatalogue"""
        self.log("Handling Resource Catalogue")
        pos = 0
        if len(data) >= 4:
            # Based on similar patterns in other handlers
            num_items = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            self.log(f"  Resource catalogue contains {num_items} items")
            # Parse each item (would need more reverse engineering for exact format)
            
    def handle_resource_cache_global_setup(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle 0xBADCAB02 - ResourceManager::cResourceCache::LoadResourceCacheGlobalSetup"""
        self.log("Handling Resource Cache Global Setup")
        pos = 0
        if len(data) >= 4:
            num_lists = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            self.log(f"  Global setup has {num_lists} resource lists")
            
            for i in range(num_lists):
                if pos + 4 > len(data):
                    break
                block_size = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                
                if pos + 64 > len(data):  # Assuming 32 wchar_t = 64 bytes
                    break
                # ResBlockType is typically 32 wide chars
                block_type_bytes = data[pos:pos+64]
                pos += 64
                # Decode as UTF-16LE (little-endian wide chars) based on data inspection
                try:
                    block_type = block_type_bytes.decode('utf-16-le').rstrip('\x00')
                except UnicodeDecodeError:
                    block_type = f"<binary: {block_type_bytes.hex()}>"
                    
                self.log(f"  List {i}: type='{block_type}', blockSize={block_size}")
                
    def handle_resource_cache_level_setup(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle 0xBADCAB03 - ResourceManager::cResourceCache::LoadResourceCacheLevelSetup"""
        self.log("Handling Resource Cache Level Setup")
        pos = 0
        if len(data) >= 4:
            num_lists = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            self.log(f"  Level setup has {num_lists} resource lists")
            
            for i in range(num_lists):
                if pos + 64 > len(data):  # sType
                    break
                s_type = data[pos:pos+64]
                pos += 64
                
                if pos + 4 > len(data):  # nBlockSize
                    break
                n_block_size = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                
                if pos + 4 > len(data):  # nNumConfigs
                    break
                n_num_configs = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                
                s_type_str = s_type.decode('utf-16-le').rstrip('\x00') if s_type else ""
                self.log(f"  List {i}: type='{s_type_str}', blockSize={n_block_size}, configs={n_num_configs}")
                
                # Parse each config name
                for j in range(n_num_configs):
                    if pos + 64 > len(data):
                        break
                    config_name = data[pos:pos+64]
                    pos += 64
                    config_str = config_name.decode('utf-16-le').rstrip('\x00') if config_name else ""
                    self.log(f"    Config {j}: '{config_str}'")
                    
    def handle_mainloop_reset(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle 0x700 - RWS::MainLoop::Reset"""
        self.log("Handling MainLoop Reset")
        
    def handle_mainloop_start_system(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle 0x70B - MainLoop::StartSystem"""
        self.log("Handling MainLoop Start System")
        
    def handle_mainloop_stop_system(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle 0x70C - MainLoop::StopSystem"""
        self.log("Handling MainLoop Stop System")
        
    def handle_mainloop_init(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle 0x71D - MainLoop::Init"""
        self.log("Handling MainLoop Init")
        
    def handle_game_database_load(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle 0x704 - Game database loading chunk"""
        self.log("Handling Game Database Load (0x704)")
        # This would set flags and call CreateEntity in the original game
        
    def handle_entity_attributes(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle 0x705 - Entity attribute update chunk"""
        self.log("Handling Entity Attributes (0x705)")
        # This would set flags and call UpdateEntityAttributes in the original game
        
    # Basic RenderWare chunk handlers (placeholders - would need more reverse engineering)
    
    def handle_rw_string(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle rwID_STRING chunk"""
        self.log(f"Handling RW String chunk, length={header.length}")
        if data:
            try:
                # Strings in RW are often null-terminated
                string_data = data.rstrip(b'\x00')
                # Try UTF-8 first, then UTF-16LE
                try:
                    text = string_data.decode('utf-8')
                except UnicodeDecodeError:
                    text = string_data.decode('utf-16-le')
                self.log(f"  String value: '{text}'")
            except Exception:
                self.log(f"  Raw data: {data.hex()}")
                
    def handle_rw_extension(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle rwID_EXTENSION chunk"""
        self.log(f"Handling RW Extension chunk, length={header.length}")
        
    def handle_rw_texture(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle rwID_TEXTURE chunk"""
        self.log(f"Handling RW Texture chunk, length={header.length}")
        
    def handle_rw_material(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle rwID_MATERIAL chunk"""
        self.log(f"Handling RW Material chunk, length={header.length}")
        
    def handle_rw_matrix(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle rwID_MATRIX chunk"""
        self.log(f"Handling RW Matrix chunk, length={header.length}")
        if header.length >= 64:  # 4x4 matrix of floats
            try:
                matrix = struct.unpack('<ffffffffffffffff', data[:64])
                self.log(f"  Matrix: [{matrix[0]:.3f}, {matrix[1]:.3f}, {matrix[2]:.3f}, {matrix[3]:.3f}, "
                        f"{matrix[4]:.3f}, {matrix[5]:.3f}, {matrix[6]:.3f}, {matrix[7]:.3f}, "
                        f"{matrix[8]:.3f}, {matrix[9]:.3f}, {matrix[10]:.3f}, {matrix[11]:.3f}, "
                        f"{matrix[12]:.3f}, {matrix[13]:.3f}, {matrix[14]:.3f}, {matrix[15]:.3f}]")
            except Exception as e:
                self.log(f"  Could not parse matrix: {e}")
                
    def handle_rw_frame(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle rwID_FRAME chunk"""
        self.log(f"Handling RW Frame chunk, length={header.length}")
        
    def handle_rw_mesh(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle rwID_MESH chunk"""
        self.log(f"Handling RW Mesh chunk, length={header.length}")
        
    def handle_rw_clump(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle rwID_CLUMP chunk"""
        self.log(f"Handling RW Clump chunk, length={header.length}")
        
    def handle_rw_atomic(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle rwID_ATOMIC chunk"""
        self.log(f"Handling RW Atomic chunk, length={header.length}")
        
    def handle_rw_light(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle rwID_LIGHT chunk"""
        self.log(f"Handling RW Light chunk, length={header.length}")
        
    def handle_rw_camera(self, header: RwChunkHeaderInfo, data: bytes):
        """Handle rwID_CAMERA chunk"""
        self.log(f"Handling RW Camera chunk, length={header.length}")


def main():
    """Main function for command-line usage"""
    if len(sys.argv) < 2:
        print("Usage: python dff_parser.py <input_file.dff> [--verbose]")
        print("Example: python dff_parser.py assets/PacificCity.dff --verbose")
        sys.exit(1)
        
    input_file = sys.argv[1]
    verbose = "--verbose" in sys.argv
    
    if not os.path.exists(input_file):
        print(f"Error: File '{input_file}' not found.")
        sys.exit(1)
        
    parser = DFFParser()
    parser.verbose = verbose
    
    print(f"Parsing DFF file: {input_file}")
    success = parser.parse_file(input_file)
    
    if success:
        print("\nParsing completed successfully!")
    else:
        print("\nParsing failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()