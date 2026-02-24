## Requirements:
- [Rexglue SDK 0.1.2](https://github.com/rexglue/rexglue-sdk)
- CMake
- Ninja
- Clang++/LLVM
- Crackdown 2 game disc
- Crackdown 2 Title Update 5


## To build:
 - Compile and install the rexglue SDK with these guest functions stubbed out: ```GUEST_FUNCTION_STUB(__imp__IoCheckShareAccess)
GUEST_FUNCTION_STUB(__imp__IoCompleteRequest)
GUEST_FUNCTION_STUB(__imp__IoDeleteDevice)
GUEST_FUNCTION_STUB(__imp__IoDismountVolume)
GUEST_FUNCTION_STUB(__imp__IoInvalidDeviceRequest)
GUEST_FUNCTION_STUB(__imp__IoSetShareAccess)
GUEST_FUNCTION_STUB(__imp__KeRestoreFloatingPointState)
GUEST_FUNCTION_STUB(__imp__KeSaveFloatingPointState)
GUEST_FUNCTION_STUB(__imp__NtCancelIoFileEx)
GUEST_FUNCTION_STUB(__imp__ObIsTitleObject)
GUEST_FUNCTION_STUB(__imp__ObReferenceObject)
GUEST_FUNCTION_STUB(__imp__RtlUpcaseUnicodeChar)
GUEST_FUNCTION_STUB(__imp__XamShowAchievementsUI)
GUEST_FUNCTION_STUB(__imp__XamShowFriendsUI)
GUEST_FUNCTION_STUB(__imp__XamShowGamerCardUIForXUID)
GUEST_FUNCTION_STUB(__imp__XamShowGoldUpgradeUI)
GUEST_FUNCTION_STUB(__imp__XamShowMarketplaceUI)
GUEST_FUNCTION_STUB(__imp__XamShowPlayerReviewUI)
GUEST_FUNCTION_STUB(__imp__XamShowPlayersUI)
GUEST_FUNCTION_STUB(__imp__XamUserCreateStatsEnumerator)
GUEST_FUNCTION_STUB(__imp__IoRemoveShareAccess)
GUEST_FUNCTION_STUB(__imp__NetDll_WSAGetOverlappedResult)
GUEST_FUNCTION_STUB(__imp__NetDll_XNetConnect)
GUEST_FUNCTION_STUB(__imp__NetDll_XNetGetConnectStatus)
GUEST_FUNCTION_STUB(__imp__NetDll_XNetQosLookup)
GUEST_FUNCTION_STUB(__imp__NetDll_XNetRegisterKey)
GUEST_FUNCTION_STUB(__imp__NetDll_XNetServerToInAddr)
GUEST_FUNCTION_STUB(__imp__NetDll_XNetUnregisterInAddr)
GUEST_FUNCTION_STUB(__imp__NetDll_XNetUnregisterKey)
GUEST_FUNCTION_STUB(__imp__XamUserGetMembershipTierFromXUID)
GUEST_FUNCTION_STUB(__imp__XamUserGetOnlineCountryFromXUID)
GUEST_FUNCTION_STUB(__imp__XamVoiceSubmitPacket)
GUEST_FUNCTION_STUB(__imp__XNetLogonGetTitleID)```
 - Extract game disc and latest title update into the assets folder. (Including its xexp file)
 - Run the codegen by using the rexglue binary in the rexglue sdk install folder: ```rexglue codegen crackdown2_config.toml```
 - ```cmake --preset win-amd64-debug; cmake --build out/build/win-amd64-debug``` in the main folder

 # Status: Not In-Game.
