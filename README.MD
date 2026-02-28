## Requirements:
- [Rexglue SDK 0.2.1](https://github.com/rexglue/rexglue-sdk)
- CMake
- Ninja
- Clang++/LLVM
- Crackdown 2 game disc
- Crackdown 2 Title Update 5


## To build:
 - Compile and install the rexglue SDK with these guest functions stubbed out: ```PPC_STUB(__imp__IoCompleteRequest)
PPC_STUB(__imp__IoDeleteDevice)
PPC_STUB(__imp__IoDismountVolume)
PPC_STUB(__imp__IoInvalidDeviceRequest)
PPC_STUB(__imp__IoSetShareAccess)
PPC_STUB(__imp__KeRestoreFloatingPointState)
PPC_STUB(__imp__KeSaveFloatingPointState)
PPC_STUB(__imp__NtCancelIoFileEx)
PPC_STUB(__imp__ObIsTitleObject)
PPC_STUB(__imp__ObReferenceObject)
PPC_STUB(__imp__RtlUpcaseUnicodeChar)
PPC_STUB(__imp__XamShowAchievementsUI)
PPC_STUB(__imp__XamShowFriendsUI)
PPC_STUB(__imp__XamShowGamerCardUIForXUID)
PPC_STUB(__imp__XamShowGoldUpgradeUI)
PPC_STUB(__imp__XamShowMarketplaceUI)
PPC_STUB(__imp__XamShowPlayerReviewUI)
PPC_STUB(__imp__XamShowPlayersUI)
PPC_STUB(__imp__XamUserCreateStatsEnumerator)
PPC_STUB(__imp__IoCheckShareAccess)
PPC_STUB(__imp__IoRemoveShareAccess)
PPC_STUB(__imp__NetDll_WSAGetOverlappedResult)
PPC_STUB(__imp__NetDll_XNetConnect)
PPC_STUB(__imp__NetDll_XNetGetConnectStatus)
PPC_STUB(__imp__NetDll_XNetQosLookup)
PPC_STUB(__imp__NetDll_XNetRegisterKey)
PPC_STUB(__imp__NetDll_XNetServerToInAddr)
PPC_STUB(__imp__NetDll_XNetUnregisterInAddr)
PPC_STUB(__imp__NetDll_XNetUnregisterKey)
PPC_STUB(__imp__XamUserGetMembershipTierFromXUID)
PPC_STUB(__imp__XamUserGetOnlineCountryFromXUID)
PPC_STUB(__imp__XamVoiceSubmitPacket)
PPC_STUB(__imp__XNetLogonGetTitleID)```
 - Extract game disc and latest title update into the assets folder. (Including its xexp file)
 - Run the codegen by using the rexglue binary in the rexglue sdk install folder: ```rexglue codegen crackdown2_config.toml```
 - ```cmake --preset win-amd64-debug; cmake --build out/build/win-amd64-debug``` in the main folder

 # Status: In-game but not playable yet.
