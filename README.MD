## Requirements:
- [Rexglue SDK 0.5.0](https://github.com/rexglue/rexglue-sdk)
- CMake
- Ninja
- Clang++/LLVM
- Crackdown 2 game disc
- Crackdown 2 Title Update 5

# Hashes
- Default.xex
 ```SHA256: 8959C449E382661D29B8EA479C685F506CD5BD3ECA40B3D73A51CC10F281069F```
- Crackdown 2 Title Update 5 xexp
 ```SHA256: A5E49FC1FF7F6F65E6F95A7B5C4B9392BB9E38674D1237AC0E2F0149D05929D7```

## To build:
 - Compile and install the rexglue SDK
 - Extract game disc and latest title update into the assets folder. (Including its xexp file)
 - Run the codegen by using the rexglue binary in the rexglue sdk install folder: ```rexglue codegen --max_jump_table_entries 519 crackdown2_config.toml```
 - ```cmake --preset win-amd64-debug; cmake --build out/build/win-amd64-debug``` in the main folder

 # Status: In-game but not playable yet.
