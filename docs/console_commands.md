# Crackdown 2 developer console commands

The retail executable keeps Ruffian's developer console. The recomp exposes it
through the hidden cheat rows at the end of Options > Display (`--c2_cheats=true`), the text box
in the F5 overlay, and the `--c2_console_startup="cmd1;cmd2"` flag. Commands are
executed by `Console_Execute` (`sub_825CE628`, console object at Core+2804 =
`0x83800AF4`). Output goes through `GDb_ConsoleOutput`; log it with
`--c2_gdb_console_output_log=true`.

This table was recovered statically from the registration calls to
`RegisterCommand` (`sub_825D0E00`, args: table, name, callback, 0, help, category)
with `tools/console_commands.py`. Names are case-insensitive in the game.

| Category | Command | Help |
|---|---|---|
| (unresolved) | `tsmalign` | align trapezoid centre line with far plane edge |
| (unresolved) | `tsmblur` | enable/disable shadow blurring |
| (unresolved) | `tsmcullmode` | set shadow cull mode |
| (unresolved) | `tsmdebugface` | set four map debug face |
| (unresolved) | `tsmdebugmap` | set debug map |
| (unresolved) | `tsmdepthbias` | set shadow depth bias |
| (unresolved) | `tsmdepthrange` | set depth range for tsmshowdepth |
| (unresolved) | `tsmearlyout` | enable/disable early out optimisations in receive shaders |
| (unresolved) | `tsmenabletrapezoid` | enable trapezoid transform |
| (unresolved) | `tsmfacescaling` | enable face scaling in four map mode |
| (unresolved) | `tsmfalloff` | set shadow distance falloff curve |
| (unresolved) | `tsmfarclip` | set shadow far clip |
| (unresolved) | `tsmfilter` | set shadow pcf filter size |
| (unresolved) | `tsmfocusdist` | set shadow focus distance |
| (unresolved) | `tsmforcenearclip` | force near clip for main rendering |
| (unresolved) | `tsmfourmaps` | enable four map mode |
| (unresolved) | `tsmfreeze` | toggle frozen shadow camera |
| (unresolved) | `tsmhalftexel` | enable/disable half texel offset |
| (unresolved) | `tsmhullclip` | set frustum hull clipping |
| (unresolved) | `tsmhullscissor` | set frustum hull scissoring |
| (unresolved) | `tsmlightdist` | set shadow light distance |
| (unresolved) | `tsmlightfar` | set shadow light far clip |
| (unresolved) | `tsmmap` | set map distance/radius |
| (unresolved) | `tsmmapsize` | set shadow maps size |
| (unresolved) | `tsmmulti` | enable/disable multi non-TSM maps mode |
| (unresolved) | `tsmmulticombined` | enable combined near/mid receive pass in multi mode |
| (unresolved) | `tsmmultidepthbias` | set multi map depth bias |
| (unresolved) | `tsmmultifarobj` | enable/disable object shadows on multi far map |
| (unresolved) | `tsmmultihalfupdate` | enable/disable half update rate on multi mid and far maps |
| (unresolved) | `tsmnearfarclip` | set use near and far camera clip planes to cull |
| (unresolved) | `tsmnearscale` | set near plane scale |
| (unresolved) | `tsmnightmode` | enable/disable night mode |
| (unresolved) | `tsmoldblend` | enable/disable old shadow blending method |
| (unresolved) | `tsmprocessdepth` | enable shadow->light depth post processing |
| (unresolved) | `tsmquantcam` | enable/disable quantization of shadow camera position |
| (unresolved) | `tsmquantlightdir` | set light direction quantization |
| (unresolved) | `tsmshadowdepth` | set shadow depth mode |
| (unresolved) | `tsmshowdepth` | show shadow depth buffer |
| (unresolved) | `tsmshowmaps` | show maps in four map mode |
| (unresolved) | `tsmshownormals` | enable/disable show normals mode |
| (unresolved) | `tsmshowshadowmap` | show shadow map texels |
| (unresolved) | `tsmslopescale` | set shadow slope scale depthbias |
| (unresolved) | `tsmtiming` | set GPU timing |
| (unresolved) | `tsmtransition` | set transition distance between near and far maps |
| (unresolved) | `tsmuseprocessbias` | enable separate process depth bias |
| (unresolved) | `tsmusetiling` | enable predicated tiling hack for four map mode |
| Activity | `activity_testtype` |  |
| Activity | `avoffset` |  |
| Activity | `avsetrad` |  |
| Activity | `avtest` |  |
| Activity | `nonphy_target` | Force Target Non-Physical |
| Activity | `nonphy_type` | Force Type Non-Physical |
| Activity | `nonphy_uid` | Force Non-Physical By UID |
| Activity | `setambientthrottlelimit` | Set the limit for throttling of ambient spawn point creation. 0.0f is no spawning, 1.0f is 100%. |
| Activity | `stresstest` |  |
| Activity | `toggleambientthrottling` | Enable/Disable throttling of ambient spawn point creation |
| AI | `autopop` |  |
| AI | `ccc` | Toggles warning of too many critical characters |
| AI | `coverpointinfo` | Displays cover point info. |
| AI | `dan` | All dans favorite settings. |
| AI | `DetectEnemies` | Enables/Disables NPCs detecting/sensing enemies. |
| AI | `DisableMiniGames` | Disables mini-game scripts. Must be set in userstartup to take effect |
| AI | `disablemissionmanager` | Disables the AI mission manager |
| AI | `DisableMissions` | Disables mission scripts. Must be set in userstartup to take effect |
| AI | `DisableVehicleDebug` | Disables all vehicle debug |
| AI | `DisableVehicles` | Disables all vehicles |
| AI | `DriveSlow` | Ambient vehicles drive at very slow speed |
| AI | `emiteventqueue` | Dumps the entire event queue to a file |
| AI | `emitevents` | Emits when events are generated |
| AI | `emitluacalls` | Emits whenever Lua is called |
| AI | `EnableAllAiVehicles` | Enables/Disables all currently spawned vehicle controllers. |
| AI | `freakpop` |  |
| AI | `IgnoreTrafficLights` | Vehicles ignore or respect traffic flights |
| AI | `mike` | So Mike doesn't have to type so much on repeated tests. |
| AI | `NPCForceHeading` | Enables/Disables forcing the heading of NPCs |
| AI | `NPCLookAt` | Enables/Disables NPC head and body lookat |
| AI | `NPCMultiWalk` | Enables/Disables NPC multi-directional walk |
| AI | `NPCTorso` | Enables/Disables kynogon auto-update of torso attribute |
| AI | `said` |  |
| AI | `sap` | Calls an agent pickup |
| AI | `scd` | Spawns a chase driver and vehicle that will chase the player |
| AI | `scp` | Show chopper paths |
| AI | `sdv` |  |
| AI | `sed` |  |
| AI | `seedadd` | DropSeedPoint |
| AI | `seedflush` | FlushSeedPoints |
| AI | `seedread` | ReadSeedPointsFromFile |
| AI | `seedrem` | RemoveSeedPoint |
| AI | `seedwrite` | WriteSeedPointsToFile |
| AI | `setaeday` | Sets the ambient event day (global) |
| AI | `SetCoverCheckTime` | Sets the delay between cover checks. |
| AI | `sgpd` |  |
| AI | `shc` |  |
| AI | `shct` | Bring the rain |
| AI | `showabreachdebug` | Shows the alternate breach debug info |
| AI | `showaccuracycones` | Shows/hides weapon accuracy cones. |
| AI | `ShowActionInput` |  |
| AI | `showaedebug` | Shows the ambient event debug |
| AI | `showagents` | Shows/hides debug info for the current brain state. |
| AI | `showaivolumes` | Shows/hides bounding volumes. |
| AI | `showanimationstrings` | Shows/hides strings above NPCs showing if they are in an animation. |
| AI | `showbehaviourdebug` |  |
| AI | `showbrains` | Shows/hides character brain debug info. |
| AI | `ShowBrakingDistance` | Display the region with in the braking distance |
| AI | `showbreachdebug` | Shows the breach debug |
| AI | `showbreachholedebug` | Shows the breach debug |
| AI | `showbullets` | Makes AI emit debug lines along bullet paths |
| AI | `showcharactergraphs` | Shows/hides local character graphs. |
| AI | `showcharacterids` | Shows/hides character IDs. |
| AI | `showcoverpoints` | Shows/hides Cover Points. |
| AI | `showcsdebug` | Cell Stronghold - Show Debug |
| AI | `showdebuglines` | Shows/hides debug lines. |
| AI | `showdebugstrings` | Shows/hides strings above each NPC containing debug info. |
| AI | `showdestinations` | Shows/hides AI paths to their current destinations. |
| AI | `showentities` | Shows/hides Kynogon entity bounding boxes. |
| AI | `showgangs` | Shows/hides AI gang debug info. |
| AI | `showglobalgraph` | Shows/hides global graph. |
| AI | `showgotopoints` | Shows/hides GoTo Points. |
| AI | `showinfoobjects` | Shows/hides Info Objects. |
| AI | `showintelliflee` | Makes intelli flee agent emit debug lines when traversing graph. |
| AI | `showistargetareaclearchecks` | Makes AI emit debug lines when testing if splash damage area around target is clear of friendlies. |
| AI | `showistargetblockedchecks` | Makes AI emit debug lines when testing if target is blocked. |
| AI | `showistargetpathclearchecks` | Makes AI emit debug lines when testing if path to target is clear of friendlies. |
| AI | `showmissiongraphs` | Shows/hides mission graphs. |
| AI | `showmovementtype` | Shows the movement type an AI is using |
| AI | `ShowNetIDInfo` | Display NPC Network ID info |
| AI | `shownp` | Shows/hides non-physical NPCs. |
| AI | `ShowNPCDigest` | Display spheres representing each NPC's network (authority/proxy) and crowd status |
| AI | `showpathchecks` | Makes pathfinder emit debug lines when testing if it can go somewhere. |
| AI | `showpatrolroutes` | Shows/hides AI patrol routes. |
| AI | `showpointlocks` | Shows/hides locked points. |
| AI | `ShowRaceInfo` | Display Racing Information |
| AI | `ShowSensedEdges` | Shows all the edges sensed by the Ai Vehicle |
| AI | `ShowSgridRoute` | Shows the route computed on the sensory grid |
| AI | `showsounds` | Shows/hides sound debug circles. |
| AI | `showsquaddebug` |  |
| AI | `showta` | Shows/hides target acquisition debug |
| AI | `showtargetinfo` | Shows/hides lines to last known AI target positions. |
| AI | `showtargets` | Shows/hides lines to AI targets. |
| AI | `showtodebug` | Tactical objectives - Show Debug |
| AI | `showtransforms` | Shows/hides crosses representing NPC transformation matrices. |
| AI | `showtraversals` | Makes traversal service emit debug lines when traversing graph. |
| AI | `ShowTurnDir` | Display the turning direction for a vehicle |
| AI | `ShowVehicleEdge` | Show vehicle current edge |
| AI | `ShowVehicleIDs` | Show vehicle IDs, <Avoidance> sensory set |
| AI | `ShowVehicleRouteNodes` | Show vehicle route nodes |
| AI | `ShowVehicleSpeed` | Displays the vehicle's speed |
| AI | `showviewcones` | Shows/hides AI view cones. |
| AI | `showvisibilitychecks` | Makes visibility service emit debug lines when testing if entity is visible. |
| AI | `skipbreachtest` |  |
| AI | `smv` | parp parp boom |
| AI | `snc_rifle` |  |
| AI | `snc_rocket` |  |
| AI | `snc_shotgun` |  |
| AI | `snc_smg` |  |
| AI | `snd` |  |
| AI | `snp_f` |  |
| AI | `snp_m` |  |
| AI | `snra` |  |
| AI | `snragi` |  |
| AI | `snrstr` |  |
| AI | `sns` |  |
| AI | `snsk` |  |
| AI | `snsl` |  |
| AI | `snsr` |  |
| AI | `spawnambienttraffic` | Spawns ambient traffic |
| AI | `spd` | Deliver in some Ninja Peacekeepers |
| AI | `sph` | Deliver some Ninja Peacekeepers |
| AI | `startvc` | Starts vehicle collection in the active zone |
| AI | `swav` | spawn attack wandering buggy |
| AI | `tocancallpk` | Tactical Objectives - Can call in Peacekeepers? |
| AI | `ToggleDebugDrawNewRagdoll` |  |
| AI | `ToggleForceNewRagdollHack` |  |
| AI | `togglenightspawn` | Toggles ambient event spawn prevention at night time |
| AI | `usedefaultspawnprototypes` | Enables or disables default AI spawn prototypes. |
| AI | `warptoinfoobject` | Warps the player to the named Info Object. |
| AI_GameDirection | `gdoff` |  |
| AI_GameDirection | `gdon` |  |
| AI_GameDirection | `gdreset` |  |
| AI_GameDirection | `gdtest` |  |
| animation | `angle` | <X rotation> <Y rotation> <Z Rotation> - anim debug thing |
| ATV Assault | `atvarmour` | ATV armour level. |
| ATV Assault | `atvmines` | ATV mine level. |
| ATV Assault | `atvrockets` | ATV rocket level. |
| ATV Assault | `atvspeed` | ATV speed level. |
| camera | `animcam` | Plays test camera anim. |
| camera | `attogocam` | Move camera attached to a game object (the player) |
| camera | `autocam` | Use camera in automatic mode |
| camera | `crcam` | Toggle camera crash mode |
| camera | `dcav` | Toggle debug camera activity volume on/off |
| camera | `fixcamera` | Use the fixed position camera |
| camera | `fixtrcam` | Use the fixed position with tracking camera |
| camera | `fly` | Enters fly mode |
| camera | `flycam` | Flythrough camera |
| camera | `flycamonsecondcontrol` | Flythrough camera |
| camera | `flymode` | Toggles between fly mode and player control mode. |
| camera | `flypad2` | Pad 2 fly camera (AV on player) |
| camera | `fpcam` | Toggle camera first person mode |
| camera | `isocam` | Toggle Iso camera mode |
| camera | `satcam` | Use the satellite camera |
| Camera | `SetDebugCamSpeed` | <SetDebugCamSpeed Value 0.5 - 5> for helicam |
| Camera | `SetDebugCamTurnMultiplier` | <SetDebugCamTurnMultiplier Value 0.5 - 5> |
| Camera | `SetDebugCamYawPitchDampen` | <SetDebugCamYawPitchDampen Value 0.8-0.99> |
| camera | `setquake` |  |
| camera | `showcamera` | Toggles display of camera positions |
| camera | `testfixedcamera` | tests fixed camera functionality |
| camera | `togglecamerasmooth` | toggles camera smoothing |
| Camera | `ToggleDebugCamFixY` | <ToggleDebugCamFixY Value> if you want the camera to only change y with triggers enable this |
| camera | `toggleh2hcamera` |  |
| Camera | `ToggleOriginalHelicam` | <ToggleOriginalHelicam Value> if you want the old dutch roll on the helicam enable this |
| camera | `togglestickytargeting` |  |
| camera | `toggletargetlag` |  |
| capture | `capdefaultfx` | Use ingame effect settings for captures |
| capture | `capforcefx` | Force special effects on for captures |
| capture | `capname` | Sets capture base filename |
| capture | `carcap_bgcolor` | Sets color key |
| capture | `carcap_camdist` | Sets cam distance from car |
| capture | `carcap_camheight` | Sets cam height |
| capture | `carcap_camoffset` | Sets lookat offset |
| capture | `carcap_cancel` | Cancels current capture |
| capture | `carcap_carrot` | Sets car rotation |
| capture | `carcap_forcecol` | Force single color |
| capture | `carcap_noplinth` | Disables the plinth |
| capture | `carcap_position` | Positions camera to capture position and displays first vehicle |
| capture | `carcap_start` | Starts capturing car images in r,g,b,black |
| capture | `carcap_test` | Test the current settings |
| capture | `moviecapture` | Does a screengrab every frame for creating movies |
| capture | `resetfc` | Resets the frame counter for output filenames back to zero |
| capture | `screencapture` | Takes a screenshot |
| capture | `screenupload` | Uploads a screenshot |
| capture | `setcaptureframe` | Sets current capture frame counter |
| capture | `setcapturetiling` | Sets horizontal & vertical screen tiling for captures |
| capture | `startmc` | Starts movie capture |
| capture | `stopmc` | Stops current movie capture |
| console | `bind` | <keypress> "<command>" Binds command to keypress |
| console | `dumpallhelp` | Displays full list of all commands |
| console | `exec` | <filename> Executes a command script |
| console | `help` | Displays list of commands in given category |
| console | `ongamestart` | <command> Store command to execute on game start |
| console | `onload` | <command> Store command to execute on level load |
| console | `search` | Searches all help commands |
| console | `stop` | Stops execution mid way through a command script file |
| Content | `toggledlcloadiffound` | Toggles whether we load DLC if found or not |
| Content | `togglelicenseoverride` | Toggles all dlc license override on / off |
| Content | `togglelicensesetting` | Toggles all dlc license setting free / paid |
| Content | `toggletransfercontent` | Toggles whether content transfer is allowed / not allowed |
| Crowd | `CrowdCarsFarCull` | Sets the crowd cars far cull dist |
| Crowd | `CrowdCarsNearCull` | Sets the crowd cars near cull dist |
| Crowd | `CrowdCarsNearFade` | Sets the crowd cars near fade dist |
| Crowd | `CrowdCarsShadowDist` | Sets the crowd cars shadow dist |
| Crowd | `CrowdFleeSpeed` | Sets the crowd flee speed |
| Crowd | `CrowdFleeTime` | Sets the crowd flee duration |
| Crowd | `CrowdLod1SwitchDist` | Sets the crowd LOD1 switch dist |
| Crowd | `CrowdLod2SwitchDist` | Sets the crowd LOD2 switch dist |
| Crowd | `CrowdLod3SwitchDist` | Sets the crowd LOD3 switch dist |
| Crowd | `CrowdLod4SwitchDist` | Sets the crowd LOD4 switch dist |
| Crowd | `CrowdLod5SwitchDist` | Sets the crowd LOD5 switch dist |
| Crowd | `CrowdMaxCount` | Sets the max crowd |
| Crowd | `CrowdSpawnRadius` | Sets the crowd |
| Crowd | `CrowdTransitionDist` | Sets the crowd transition dist |
| Crowd | `disablecrowd` | Disables Crowd |
| Crowd | `exitcrowd` | exit crowd type |
| Crowd | `reallydisablecrowd` | Disables Crowd... for real this time |
| Crowd | `Setcrowddeathexplosionheight` | Set Crowd Death Explosion Height |
| Crowd | `setcrowddeathexplosionradius` | Set Crowd Death Explosion Radius |
| Crowd | `setcrowddeathexplosionwidth` | Set Crowd Death Explosion Width |
| Crowd | `setcrowddeathfallfadeoffset` | Set Crowd Death Fall Fade offset |
| Crowd | `setcrowddeathfallfadetime` | Set Crowd Death Fall Fade time |
| Crowd | `setcrowddeathgravity` | Set crowd death gravity |
| Crowd | `setcrowddeathparabolafadeoffset` | Set Crowd Death Parabola Fade offset |
| Crowd | `setcrowddeathparabolafadetime` | Set Crowd Death Parabola Fade time |
| Crowd | `setcrowddeathrotationy` | Set Crowd Death Rotation Y |
| Crowd | `setcrowddeathrotationz` | Set Crowd Death Rotation Z |
| Crowd | `setzoneindexdensity` | Set Zone Index Density |
| Crowd | `setzoneindexnightdensity` | Set Zone Index Night Density |
| Crowd | `setzonenamedensity` | Set Zone Name Density |
| Crowd | `setzonenamenightdensity` | Set Zone Name Night Density |
| Crowd | `spawncrowd` | spawn crowd type |
| Crowd | `togglecrowd` | toggle crowd |
| crowd | `togglecrowdblue` | toggle crowd rendering |
| crowd | `togglecrowdcars` | toggle crowd car rendering |
| Crowd | `togglecrowdcells` | Toggle crowd cells |
| Crowd | `togglecrowdcol` | Disable crowd collisions |
| Crowd | `togglecrowddeath` | Toggle Crowd Death System |
| Crowd | `togglecrowdfd` | Toggles crowd full debug mode |
| Crowd | `ToggleCrowdLodDisplay` | Sets the crowd transition dist |
| Crowd | `togglecrowdroutecount` | Toggle crowd route count |
| Crowd | `togglecrowdroutes` | Toggle crowd routes display |
| Crowd | `togglecrowdtransitions` | Toggle crowd transitions |
| Crowd | `togglecrowdvariation` | Toggle crowd variation |
| Crowd | `toggledaytimecrowd` | Toggles crowd on/off during the day |
| Crowd | `togglefarcars` | Toggles distant vehicles |
| Deluge | `completewave` | Complete Current Wave immediately |
| Deluge | `dumphordedata` | Dump horde npc and vehicle data to the spew. |
| Deluge | `edluge` | Start a wave with fixed time, no crowd |
| Deluge | `givesunburstpowerup` | Give sunburst power up. |
| Deluge | `settime` | Set time remaining (seconds) |
| Deluge | `startwave` | Start Deluge Wave - Zone, Wave, NumPlayers |
| Deluge | `TogglePBM` | Toggle points based multiplier rather than combo based. |
| Deluge | `ToggleSNK` | Toggle killing of NPCs deemed to be stuck in the enivornment. |
| Deluge | `zoneleveling` | Toggle linking player skill levels to the deluge zone number. |
| Equipment | `equipnetinterp` |  |
| GameManagement | `cancelpgc` |  |
| GameManagement | `starttier` | Overrides the initial mission tier for campaign games. Usage: starttier <TierIndex> |
| GameManagement | `testpgc` |  |
| GameManagement | `toggleminigames` |  |
| GameManagement | `togglerenegadesdebug` |  |
| GameManagement | `unlockminigametiers` |  |
| gamemanager | `exit` | Gracefully exit the game |
| gamemanager | `exitnow` | Exit the game immediately, without shutting down |
| gamemanager | `quit` | Gracefully exit the game |
| gamemanager | `quitnow` | Exit the game immediately, without shutting down |
| gamemanager | `reboot` | Exit the game immediately, without shutting down |
| GDG | `addrescacheconfig` | Sets up alternate Resource Cache config numbers (GDG Only) |
| GDG | `saveclasshierarchy` | dumps out classes.txt for use with GDG |
| GOM | `classhierarchy` | <class> Draw the class hierarchy from the given root. Shows Principal spawn type of spawnable classes in brack |
| GOM | `listpt` | List all registered Prototypes |
| GOM | `sizeof` | <class> Show size of class in bytes |
| GSM | `ignore_dlc_resources` | Ignores checks for available resources when activating DLC |
| GSM | `purchase_dlc` | Simulates purchase of a DLC offer |
| HUD | `toggleshowhudinscreenshots` | Toggle the showing of HUD in screen shots |
| Input | `minp` | Binds input key(s) to an action |
| Input | `toggledebuginput` | Toggle Debug Input for Final |
| LIVE | `sethostprobability` | Sets up hosting probabilities for Quick Match. Args [active 0/1] [probability start 0-1] [probability scale] [ |
| LIVE | `setminplayers` | Set minimum players needed to access a public game |
| misc | `bbdebug` | Billboard debug on/off |
| misc | `bbdummy` | Billboard dummy text on/off |
| Misc | `clearmem` | [1 or 0] Enables / Disables ClearMem |
| misc | `cmdbuf` | Enables or disables command buffers (bit0=record, bit1=use) |
| misc | `controlgraph` | Toggles or explicitly sets drawing control graph on or off |
| misc | `decmorphtarget` | Sets morph damage target for Damage Morph manager debugging |
| misc | `demotimeout` | Sets demo timeout time in seconds |
| misc | `emptycity` | Starts the game in an empty city |
| misc | `envcol` | Toggle Static Environment Collision display |
| Misc | `extranetworklogging` | [1 or 0] Enables / Disables SyncDebugger |
| misc | `fastrender` | Toggle Fast Rendering |
| misc | `flushcmdbuf` | Flush all command buffers |
| misc | `forcelowtextures` | Forces usage of low-memory textures - only valid from userstartup.ini |
| misc | `forceunlocksupplypoints` | Unlocks all supply points |
| misc | `globallevel` | changes global file |
| Misc | `gputiming` | Show GPU timing |
| misc | `hideskinned` | Toggles displaying skinned clumps |
| misc | `ignorecmdbuf` | Ignore pre-built command buffer data (once enabled can never be undone) |
| misc | `impound_vehicles` | Enables/disables vehicle impounding in the Agency Garageprops |
| misc | `incmorphtarget` | Sets morph damage target for Damage Morph manager debugging |
| misc | `inflatefail` | Toggles or explicitly sets inflation failure testing on or off |
| misc | `intextinfo` | Toggles or explicitly sets display of interior/exterior info |
| misc | `lua` | Executes a chunk of lua script.script |
| misc | `luafile` | Executes a lua script filescript |
| misc | `luagc` | Forces Lua to garbage collect.script |
| Misc | `NetThreaded` | Set whether Net Threaded |
| Misc | `NetVersion` | Set the Net version |
| misc | `nullroot` | Finds props with dummy NULL root nodesprops |
| Misc | `perfgraph` | Show CPU/GPU performance graphs |
| misc | `playbackrapfile` | plays back a RAP file |
| misc | `posinfo` | Toggles or explicitly sets display of player position info |
| misc | `recassert` | <n> recurses n times, then ASSERTs false |
| misc | `recordandplayback` | Records your game and then when you quit and extract it replays it again and again |
| misc | `resourcethrash` | Toggles or explicitly sets performing resource thrash on level startup |
| misc | `safearea` | Toggles or explicitly sets drawing of TCR safe area on or off |
| misc | `scriptprofile_frames` | Profiles script usage over a given number of frames.script |
| misc | `SetGameDifficulty` | Sets Game Difficulty level |
| misc | `setmorphtarget` | Sets morph damage target for Damage Morph manager debugging |
| Misc | `SetPresentImmediateThreshold` | <SetPresentImmediateThreshold Value> - 0 for no tearing, 100 for allow tear |
| Misc | `SetVehicleLod1DistOveride` | <SetVehicleLod1DistOveride Value> - sets the distance in m of the lod1 car transition |
| misc | `showskeletons` | Toggles displaying object hierarchies |
| misc | `spawntiming` | Toggles or explicitly sets spawn timing on or off |
| Misc | `syncdebugger` | [1 or 0] Enables / Disables SyncDebugger |
| misc | `texdamarea` | Toggle Texture Damage Areas on/off |
| Misc | `textscale` | <Scale Value> - scale text for poor TVs |
| Misc | `ToggleAndrewKePerfTest` | enable disables collection of perf options |
| misc | `ToggleBertCam` | Toggles or explicitly sets Bert Cam. |
| misc | `ToggleBertMovement` | Toggles or explicitly sets Bert Movement Mode. |
| Misc | `ToggleBlackShirt` | <ToggleBlackShirt Value> |
| Misc | `ToggleCameraRayCastOptimization` | enable disable raycast optimization code for camera |
| misc | `togglecolE3` | Disable E3 Barrier |
| misc | `toggledeathcam` | Toggle deathcam mode |
| misc | `toggledebugtools` | Toggle rendering of debugtools |
| misc | `toggledisplaydamage` | Toggles display of damage values |
| misc | `ToggleInfiniteWorld` | Toggles or explicitly sets the world edge mode. |
| misc | `toggleorbs` | Toggles agility/hidden orbs |
| Misc | `TogglePVPDamage` | Toggle the PVP damage system that permits PVP Head shots and leg shots |
| misc | `toggletoddoors` | Enables/disables time-of-day door controlprops |
| Misc | `ToggleVehicleLod1DistOveride` | enable disables the overide |
| Misc | `ToggleVehicleSortOptimization` | enable disable sort optimization |
| misc | `usehdcache` | Toggles usage of hard disk cacheing |
| misc | `vlock` | toggles vlock |
| misc | `vsync` | toggles vsync |
| Mission | `unlockmissiontier` |  |
| Mission | `unlockmissiontiers` |  |
| Movie | `ShowOutro` | Shows the outro |
| Network | `disconnectnode` | Disconnects a particular node from our network |
| Network | `forcenetversion` |  |
| Network | `kicknode` |  |
| Network | `maxplayers` |  |
| Network | `netbodyreploptim` |  |
| Network | `nethost` | Host a network game. Usage: nethost |
| Network | `netjoin` | Join a network game. Usage: netjoin "hostIP" |
| Network | `netsecurity` | Toggles network security on/off. Usage: netsecurity "value (0/1)" |
| Network | `npclb` |  |
| Network | `reloadpriorityfile` |  |
| Network | `setbadnetworkpacketloss` |  |
| Network | `setpeertimeout` | Sets the timeout for a peer connection attempt |
| Network | `togglebadnetwork` |  |
| Network | `togglepriority` |  |
| Network | `togglereliable` |  |
| Network | `xrnmsetopt` | Sets an xrnm option. Usage: xrnmsetopt "optionID" "optionValue" |
| Network | `xrnmsetoptall` | Sets an xrnm option. Only use on the host. Will send to all clients. Usage: xrnmsetoptall "optionID" "optionVa |
| networking | `dumpreplicationtocsv` | Dump Replication System Information to CSV files |
| networking | `ignorenetworkdisconnects` | Toggle handling of network disconnects. |
| networking | `netcardebug` | Toggle car motion debugging |
| networking | `netmon` | Toggle the network performance monitor. Optional param: verticle offset line for display. |
| networking | `netmonreset` | Reset the stats in the network monitor |
| networking | `netsetsampleinterval` | Set the time in ms between each network logging and sampling |
| networking | `networkinvitedelaycase` | Set the test case to delay an incoming invite |
| networking | `networklimitsendrate` | Set the Max send rate |
| networking | `networklog` | Log and entry into the networking log. requires prior activation of logging through networkstartlogging. |
| networking | `networksetmaxplayerload` | set the max number of players before props are deleted in a network game. |
| networking | `networksetmaxpropload` | set the max number of props before props are deleted in a network game. |
| networking | `networktoggledebugmode` | Toggle debug mode on and off so disconnects don't happen while debugging. |
| networking | `networktogglelinklogging` | Toggle on and off logging networking information and per link data |
| networking | `networktogglelogging` | Toggle on and off logging networking information |
| networking | `networktogglepacketthrottling` | Toggle throttling messages to 15Hz on and off. |
| networking | `resetreplicationcounters` | Reset Replication System Counters |
| networking | `togglecoalescing` | Toggle coalescing of messages on and off. |
| networking | `ToggleNewInterpolation` |  |
| networking | `ToggleVehicleInterpMode` | toggle the vehicle interp mode |
| Performance | `runfast` | Toggles or sets whether to run fast or normally, by running the command scripts RunFast.ini and UndoRunFast.in |
| Performance | `setscaler` | <name> <value> - Sets the named performance scaler to the specified value |
| Physics | `blowtyre` | Blow selected tyre of players vehicle |
| physics | `HavokTimers` | Sets Havok Timers on or off |
| physics | `HavokVisualDebugger` | Sets Havok Debugger on or off |
| Physics | `inflatetyre` | Inflate selected tyre of players vehicle |
| Physics | `ppptool` | Sets PPP Tool on or off |
| physics | `resetmetrics` | Resets Vehicle Metrics (0-60 times etc) |
| Physics | `showlpt` | Toggles launch pad trajectory rendering |
| physics | `VehicleLearningEnabled` | Sets vehicle learning on or off |
| physics | `VehicleTraining` | Sets vehicle training on or off |
| player | `addweapon` | Gives the player a specified weapon |
| player | `allskills` | Explicitly set all player's skills |
| player | `apocalypse` | Kill all bots (player takes credit) |
| player | `athleticbonus` | Add bonus to player's athletic skill |
| player | `athleticskill` | Explicitly set player's athletic skill |
| player | `combust` | The target combusts |
| player | `damagehealth` | Toggles damage effect on health |
| player | `decallskills` | Decrements player's athletic skill |
| player | `decathleticskill` | Decrement player's athletic skill |
| player | `decdrivingskill` | Decrement player's driving skill |
| player | `decexplosiveskill` | Decrement player's explosives skill |
| player | `decfightingskill` | Decrement player's fighting skill |
| player | `decfirearmskill` | Decrement player's firearms skill |
| player | `deleteallweapons` | Delete all weapons that the AI have. |
| player | `deletegameobject` | Calls DeleteGameObject() on player's target |
| player | `dohcspin` | Sets/toggles helicam spin mode |
| player | `drivingbonus` | Add bonus to player's driving skill |
| player | `drivingskill` | Explicitly set player's driving skill |
| player | `explosivebonus` | Add bonus to player's explosives skill |
| player | `explosiveskill` | Explicitly set player's explosives skill |
| player | `fightingbonus` | Add bonus to player's fighting skill |
| player | `fightingskill` | Explicitly set player's fighting skill |
| player | `FindPlayerPos` | transports player to new position |
| player | `firearmbonus` | Add bonus to player's firearms skill |
| player | `firearmskill` | Explicitly set player's firearms skill |
| player | `god` | Toggles player character invulnerable to damage |
| player | `hcspincenter` | Sets the focu point for helicam spin |
| player | `hcspinradius` | Sets the radius for helicam spin (m) |
| player | `hcspinspeed` | Sets the speed for helicam spin (degrees/sec) |
| player | `incallskills` | Increment player's athletic skill |
| player | `incathleticskill` | Increment player's athletic skill |
| player | `incdrivingskill` | Increment player's driving skill |
| player | `incexplosiveskill` | Increment player's explosives skill |
| player | `incfightingskill` | Increment player's fighting skill |
| player | `incfirearmskill` | Increment player's firearms skill |
| player | `infiniteammo` | Give player infinite ammo |
| player | `instagib` | Instantly kills player's target |
| player | `leigh` | Leigh's fast setup |
| player | `loaded` | Gives the player all available equipment |
| player | `maxagentskills` | Explicitly set all player's skills to max |
| player | `playbackhelicam` |  |
| player | `possess` | Player takes posession of their target |
| player | `rain` | Sets it to rain around the player |
| player | `reboot` | Reboots the console, starting the game exe again |
| player | `recordhelicam` |  |
| player | `reloadshaders` | Reload all shaders from disk |
| player | `resetme` | Resets the debug player |
| player | `ResetPlayerRot` | resets player rotation to identity |
| player | `revertshaders` | Revert shaders to pre-built |
| player | `scalechar` | Scales the player's target (if it's a character) |
| player | `scaleplayer` | scales the player |
| player | `setarmour` | Set player character's armour |
| player | `sethealth` | Set player character's health |
| player | `setonfire` | Sets the players target on fire |
| player | `skilltimescale` | (value) Sets the skill Time Scale |
| player | `spawnthrash` | <class> thrash spawning for a given principal type |
| player | `squadbonus` | Add bonus to player's squad skill |
| player | `StunAllCharacters` | Stun all the AI characters in the volume. |
| player | `suicide` | Player character instantly dies |
| player | `summon` | <prototype name> Summon prototype |
| player | `summondamaged` | <prototype name> Summon prototype |
| player | `takedamage` | Player character takes given amount of damage |
| player | `TeleportPlayer` | transports player to new position (`TeleportPlayer x,y,z`, comma separated; prints `Pos was`/`Pos now`) |
| player | `togglespawn` | Toggles spawn points active and incative |
| player | `ToggleTargeting` | Toggle on Screen targeting |
| player | `transformplayer` | tests transform vfx |
| player | `unlock_supply_points` | Unlocks all agency supply points |
| player | `widescreen` | Toggles aspect between 4:3 and 16:9 |
| props | `dingdong` | ding dong like a bell |
| props | `killrotmotor` | kills a targeted cHinged props motor |
| props | `logpropswithnospawnpoints` | Logs the prototype names of all props that do not have an associatedspawn point to a file in the logfiles dire |
| props | `makepropexplosive` | Makes a targeted prop explosive |
| props | `rottomax` | rotates a targeted cHinged prop to maximum extents |
| props | `rottomin` | Slides a targeted cHinged prop to minimum extents |
| props | `slidefree` | Makes a targeted cPrismatic prop slide freely |
| props | `slidetomax` | Slides a targeted cPrismatic prop to maximum extents |
| props | `slidetomin` | Slides a targeted cPrismatic prop to minimum extents |
| props | `spinAnticlockwise` | rotates a targeted cSpinning prop Anticlockwise |
| props | `spinclockwise` | rotates a targeted cSpinning prop clockwise |
| props | `toggleconstraintdebug` | Displays prop constraint debug |
| props | `togglepathobjectdebug` | Displays prop path object debug |
| render | `3drender` | Toggles the 3d render on and off |
| Render | `aicharpixelcount` | Display pixel counts for AI chars |
| Render | `allowrender` | [1 or 0] Enables / Disables rendering |
| Render | `customlighting` | Selects custom lighting slot |
| Render | `defaultnr` | Toggles/Sets default state for renderability of Activity Volumes |
| Render | `disablecustomlighting` | Disables custom lighting slot |
| Render | `disableforceskytod` | Stop forcing sky TOD |
| render | `drawaabb` | Toggles / Sets rendering AABBs instead of RenderObjects |
| Render | `drawnr` | Toggles/Sets debug drawing of non-renderable game objects |
| render | `fadeout` | Fades out target graphic |
| render | `forcelod` | Forces renderer to display a specific LOD |
| Render | `forceskytod` | Forces sky time of day |
| Render | `longview` | Disable distance culling in game renderer |
| Render | `outlinemode` | set outline mode 1=regular, 2=2xaa depth/normal, 3=4xaa depth only |
| Render | `SaveVisualSettings` | Saves visual settings to disk |
| Render | `setgammaramp` | Set the gamma ramp |
| Render | `shadvolume` | Toggles shadow volume display |
| Render | `toggleafterlights` | Toggle rendering of afterlights |
| Render | `togglealphapass` | Toggle the alpha render pass |
| Render | `togglebarrier` | Disable rendering of barrier |
| Render | `togglebloom` | Disable rendering of bloom |
| Render | `toggleclip` | Toggle clipping in GameRenderer |
| Render | `toggleclutter` | Toggle rendering of clutter |
| Render | `toggleepilogdepthresolve` | Toggle epilog depth resolve |
| Render | `togglegloballights` | Toggle rendering of global lights |
| Render | `toggleocc` | Enable/Disable occlusion testing |
| Render | `toggleopaquepass` | Toggle the opaque render pass |
| Render | `toggleoutlines` | Disable rendering of outlines |
| Render | `toggleparticleafterlights` | Toggle particle rendering of afterlights |
| Render | `toggleshadows` | Toggle rendering of shadows |
| Render | `togglewatere3hack` | Toggle the water render pass |
| Render | `togglewaterpass` | Toggle the water render pass |
| render | `trackdirty` | Toggles / Sets display of tracking sources of cLODClump::SetDirty() |
| render | `transbias` | Set LOD transition depth bias |
| Replay | `DeleteRunNumFile` | Zeros the run number for the next run. |
| Replay | `killreplay` | Kills recording/playback of replays. |
| Replay | `loopplayback` | Loops replay playback indefinately |
| Replay | `noreplay` | Deactivates the replay component (startup.) |
| Replay | `playback` | Initialises playing back of a replay file (startup.) |
| Replay | `record` | Initialises recording of a replay file (startup). |
| Replay | `replaydisable` |  |
| Replay | `replayenable` |  |
| Resource | `dumprescache` | Dump contents of resource cache to console |
| Resource | `dumprescat` | Dump contents of resource catalogue to console |
| RPG | `targetingcurve` | Targeting Curve Rate 2D distance and 3D distance |
| RPG | `targetingrate` | Targeting Rate 2D distance and 3D distance) |
| RPG | `viewconeangle` | View Cone Angle (degrees) |
| RPG | `viewconeposition` | View Cone Position |
| s mode | `tsmprocessbias` | set separate process detph bias |
| scatter | `scatteratoc` | Use alpha to coverage |
| scatter | `scatterbox` | Show scatter bound boxes |
| scatter | `scatterbright` | Set scatter afterlight brightness |
| scatter | `scatterdepth` | Enable scatter depth pass |
| scatter | `scatterenable` | Enable scatter |
| scatter | `scatterscissor` | Scissor scatter |
| scatter | `scattersubsplit` | Enable scatter sub group splitting |
| Script | `editscripts` | Toggles / sets whether scripts will be loaded individually off disk. Must be set in userstartup to take effect |
| script | `emitluafileaccess` | Turns on/off lua file access emits |
| script | `preprocessscripts` | Turns on/off preprocessing of lua scripts |
| Script | `ScriptDebuggerOn` | Decides whether ScriptDebugger should be run |
| script | `scriptprofile_start` | Starts profiling script. Stop profiling script with scriptprofile_stop |
| script | `scriptprofile_stop` | Stops profiling script. Start profiling script with scriptprofile_stopAn optional string parameter supplies th |
| script | `setscripterrorlevel` | Sets what action the script system takes when an error occurs: 0-no action, 1-emits, 2-warns, 3-asserts |
| Session | `defaultlevel` | Sets the default level to load. Standard: pacificcity. Usage: defaultlevel levelname |
| Session | `ForceJoinOption` | Sets which players are allowed to join the session. |
| SkillPickup | `createskillpickups` |  |
| SkillPickup | `toggleskillpickuptest` |  |
| SpeedTree | `togglespeedgrass` | Disable rendering of speedgrass |
| spew | `spewdisable` | Disable all spew output |
| spew | `spewenable` | Enable all spew output |
| spew | `spewexclude` | Add one or more new spew exclusions |
| spew | `spewincclear` | Clears entire list of spew inclusions |
| spew | `spewinclist` | Lists entire list of spew inclusions |
| spew | `spewinclude` | Add one or more new spew inclusions |
| Squad | `disablesquadsinpvp` | Disable squad spawning in PVP games. |
| Squad | `showcriticalsquadspew` | Enable critical debug spew for squads. |
| Stats | `resetstats` | Clear terminal game stats |
| Stats | `stats` | Write out current game stats |
| system | `assert` | [rws] Asserts using ASSERT by default, or RWS_ASSERT if rws argument given |
| system | `CommitMemoryLog` | forces a commit for the memory log so we know it's up-to-date |
| System | `disablecrashhandler` | Disables Crash Handler |
| system | `exception` | Causes an access violation |
| system | `fps` | Toggles on-screen FPS counter |
| system | `gpufence` | Toggle GPU fence |
| system | `helicam` | Toggles HeliCam mode (not to be confused with player fly camera) |
| system | `helifov` | Sets HeliCam FOV |
| system | `NewDesignBuild` | Sets new method for design builds on or off |
| system | `NewStartPoints` | Use new old old start posisitions |
| system | `oldheli` | Resets helicam setup to pre CD2 DLC |
| system | `pause` | Pauses game logic |
| system | `pausecam` | Sets/toggles panning camera when paused |
| system | `rwslisten` | Toggle listening for Renderware Studio remote connection |
| system | `setfps` | Set FPS |
| system | `setrescacheconfig` | Sets resource cache configuration |
| system | `shadow` | Set shadow mode (0/1/2) |
| system | `speeddn` | Decreases desired FPS (to min 1) |
| system | `speedup` | Increases desired FPS (to max 30) |
| system | `stepframe` | Advances game logic one frame and then pauses |
| system | `tilingmode` | Change tiling mode (0, 1, or 2) |
| System | `ToggleAsserts` | Enables/Disables asserts |
| system | `togglehdcache` | Toggle HD caching of data on and off |
| system | `usesecondcontrollerforhelicam` | Toggles use of second controller for controlling helicam |
| System | `vehicleshadowbias` | Set vehicle shadow bias |
| system | `warning` | <Message> Displays a warning with the given message |
| targeting | `subtargetdown` | Performs subtarget-down action |
| targeting | `subtargetleft` | Performs subtarget-left action |
| Targeting | `subtargets` | Toggle display of all available subtargets |
| targeting | `subtargetup` | Performs subtarget-up action |
| Targeting | `targetinfo` | Toggle display of target size and speed |
| targeting | `TargetObjectInfo` | Display details of locked target |
| Targeting | `targetpriorities` | Toggle display of target priorities |
| targeting | `toggleprecisionaimdebug` |  |
| targeting | `UntargetObject` | Targeting-Override Unlock from target |
| TimeOfDay | `tode3advance` | Advance the time of day, setting shadows as appropriate for the E3 build. |
| TimeOfDay | `tode3setphase` | Set the time of day, setting shadows as appropriate for the E3 build.  Phase is same as todsetphase, but the v |
| TimeOfDay | `todfup` |  |
| TimeOfDay | `todsetperiod` | Set the time of day period (mins IRL) |
| TimeOfDay | `todsetphase` | Set current time of day phase (0.0 to 1.0) |
| TimeOfDay | `todsetrandomphase` | Select a random time of day |
| TimeOfDay | `todtoggle` | Toggles the time of day cycle on/off |
| tsm | `tsmdebugtrapezoid` | toggle trapezoid debug display |
| UI | `forceshowbadconnectionhud` | Forces the Bad connection HUD to display |
| UI | `gamemodeshortcut` | Sets game mode shortcut |
| UI | `hideskillhud` | Hides specific skill hud |
| UI | `pingnearbyorbs` | Pings nearby orbs, within radius specified |
| UI | `setfontscalefactor` | Sets the Scaleform font scale factor for the main font |
| UI | `setHUDopacity` | Sets the opacity of the HUD in percent |
| UI | `setskillhudzero` | Set specific skill hud to zero |
| UI | `showgangmarkers` | Shows/Hides Gang markers above AI |
| UI | `showskillhud` | Shows specific skill hud |
| UI | `showstunttext` | Show stunt completion text. Args: [stunt type] [current] [total] |
| UI | `toggleAllowForceHost` | Toggles whether the force host option is available |
| UI | `toggleConference` | Toggles Conference config |
| UI | `toggleFullFlow` | Toggles UI flow |
| UI | `toggleHUD` | Toggles HUD on / off |
| UI | `togglePrompts` | Toggles HUD prompts |
| UI | `toggleVideo` | Toggles billboard videos, call before entering game. |
| UI | `ui_showalllogs` | Shows all logs on the UI map screen |
| UI | `ui_showallorbs` | Shows all logs on the UI map screen |
| UI | `unlockdelugewaves` |  |
| UI | `unsetskillhudzero` | Reset specific skill hud from zero |
| UI | `writeLeaderboard` | Writes to the Road Race leaderboard |
| vehicle | `closecarcomponent` | Closes a car component |
| vehicle | `opencarcomponent` | Opens a car component |
| vehicle | `smashglass` | Smashes targetted vehicle's glass components |
| vehicle | `togglecarbreakup` | Toggle car breakup |
| vehicle | `togglecarconstraintdisplay` | Displays car constraint debug drawing |
| vehicle | `toggledmorphdebug` | Debug graphics for dmorph |
| vfx | `afterlighttiming` | Enable afterlight GPU timing |
| vfx | `attach_particles` | Attach effect to player |
| vfx | `decalfade` | Set decal fade time |
| vfx | `decalfalloff` | Set decal falloff exponent |
| vfx | `decalrange` | Set decal fade range |
| VFX | `decreasecloudiness` | Clear up the sky |
| VFX | `dont_load_particles` | Stop particle effects being loaded |
| VFX | `downsampleparticles` | downsample particles 0=no 1=yes (default) |
| VFX | `downscaleafterlights` | enable afterlight downscaling |
| vfx | `enable_particles` | 0=fail all particle effect spawns 1=enable particle effect |
| vfx | `forcewatervis` | force water to not be visible |
| vfx | `gotoantiwater` | go to anti-water box |
| vfx | `gotowater` | go to water box |
| vfx | `grblock` | God Rays Cloud Block Factor |
| vfx | `grfalloff` | God Rays Falloff Factor |
| vfx | `grmagf` | God Rays Magnification Factor |
| vfx | `grmode` |  |
| vfx | `grraysize` | God Rays Size |
| vfx | `grsurfdiv` | God Rays Resolution (Surface divisior) |
| vfx | `grtry` |  |
| VFX | `increasecloudiness` | Become overcast sky |
| VFX | `instantclearcloudy` | Change in the sky |
| vfx | `kill_deity_ray` | Terminate test deity ray effect |
| vfx | `load_particles` | Load particle effect |
| vfx | `nextantiwater` | go to next anti-water box |
| vfx | `nextwater` | go to next water box |
| VFX | `particlebuffersize` | size of particle buffer (0, 1, 2, 3, 4): 0 - biggest (default), 4 - smallest |
| vfx | `pausedecal` | Pause decal system |
| vfx | `rebuilddecal` | Rebuild decal shader |
| VFX | `reloadcrowdshaders` | reload crowd shaders |
| VFX | `reloadfarheadlights` | Reload Far HeadLights |
| VFX | `reloadskydomeshaders` | reload skydome shaders |
| vfx | `scissorwater` | scissor all water pixels |
| VFX | `setclearweather` |  |
| VFX | `setcloudyweather` |  |
| VFX | `setgpr` | nuber of gprs to use (default), 36 |
| VFX | `setovercastweather` |  |
| VFX | `setrandomweather` |  |
| vfx | `settracers` |  |
| vfx | `settrails` |  |
| vfx | `ShowRopeSegments` |  |
| vfx | `test_deity_ray` | Create test deity ray effect |
| vfx | `test_deity_ray_colour` | Set colour for test deity ray effect |
| vfx | `test_deity_ray_falloff` | Set falloff parameters for test deity ray effect |
| vfx | `test_deity_ray_occlude_mip_falloff` | Set occlude mip falloff for test deity ray effect |
| vfx | `test_deity_ray_world_space_falloff` | Set world space falloff for test deity ray effect |
| vfx | `test_particles` | Test particle system |
| vfx | `testdecal` | Test spherical decal |
| VFX | `testfixuptod` |  |
| vfx | `testhemidecal` | Test hemispherical decal |
| vfx | `testplanardecal` | Test planar decal |
| vfx | `toggle_dof` | Toggle DOF effect |
| vfx | `togglemotionblur` | Toggle motion blur |
| VFX | `toggleparticlealpha` | Disables alpha for particles - useful for debug purposes |
| VFX | `toggleweather` |  |
| VFX | `unittestfixuptod` |  |
| vfx | `unload_particles` | Unload particle effect |
| vfx | `water` | Set water const |
| vfx | `watergrid` | Set high detail water grid dim |
| world | `togglelod4env` | Toggles or specifically sets drawing of LOD4 environment |
