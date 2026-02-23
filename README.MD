## Requirements:
- [Rexglue SDK 0.1.2](https://github.com/rexglue/rexglue-sdk)
- CMake
- Ninja
- Clang++/LLVM
- Crackdown 2 game disc
- Crackdown 2 Title Update 5


## To build:
 - Extract game disc and latest title update into the assets folder. (Including its xexp file)
 - Run the codegen by using the rexglue binary in the rexglue sdk install folder: ```rexglue codegen crackdown2_config.toml```
 - ```cmake --preset win-amd64-debug; cmake --build out/build/win-amd64-debug``` in the main folder

 # Status: Not In-Game.
