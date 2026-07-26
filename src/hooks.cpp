#include <rex/cvar.h>
#include <rex/hook.h>
#include <rex/system/format.h>

// //https://github.com/rexglue/rexglue-sdk/issues/121
// void FixBrokenSwitchTable_82812FA4(PPCRegister& r3) {

// 	switch (r3.u32) {
// 	case 0:
// 		r3.s64 = 2;
// 		break;
// 	case 1:
// 		r3.s64 = 1;
// 		break;
// 	default:
// 		r3.s64 = 1;
// 		break;
// 	case 3:
// 		r3.s64 = 0;
// 		break;
// 	case 2:
// 		r3.s64 = 3;
// 		break;
// 	case 0xc:
// 		r3.s64 = 3;
// 		break;
// 	}
// }

REXCVAR_DEFINE_BOOL(c2_fps_display, false, "Debug", "Displays the game's debug fps overlay.");
REXCVAR_DEFINE_BOOL(c2_perf_graph_display, false, "Debug", "Displays the game's debug performance graph overlay.");
REXCVAR_DEFINE_BOOL(c2_gdb_console_output_log, false, "Debug", "Log GDb_ConsoleOutput calls");
REXCVAR_DEFINE_BOOL(c2_resource_log, false, "Debug", "Log what resources get loaded and what functions handle them.");

bool force_fps_display() { 
    return REXCVAR_GET(c2_fps_display);
}

bool force_perf_graph_display() {
    return REXCVAR_GET(c2_perf_graph_display);
}

REX_HOOK_RAW(GDb_ConsoleOutput) {
    uint32_t format_ptr = ctx.r3.u32;
    if (!format_ptr) {
        ctx.r3.s64 = -1;
        return;
    }

    auto format = rex::memory::GuestPtr<const u16*>(base, format_ptr);

    rex::system::format::StackArgList args(ctx, base, 1);   // varargs start at r4 (index 1)  
    rex::system::format::WideStringFormatData data(format);

    int32_t count = format_core(base, data, args, true);  // true = wide  
    if (REXCVAR_GET(c2_gdb_console_output_log) && count > 0) {
        auto wstr = data.wstr();
        // wstr is std::wstring; narrow for logging (fine for ASCII debug output)  
        std::string narrow(wstr.begin(), wstr.end());
        while (!narrow.empty() && std::isspace((unsigned char)narrow.back()))
            narrow.pop_back();
        REXLOG_DEBUG("GDb_ConsoleOutput: {}", narrow);
    }
}

void Hook_RWS_HandlerFound(
    PPCRegister& r3,
    PPCRegister& r27,
    PPCRegister& r30,
    PPCRegister& r31)
{
    if (!REXCVAR_GET(c2_resource_log))
        return;

    uint8_t* base = rex::system::kernel_state()->memory()->virtual_membase();
    using namespace rex::memory;

    const char* name = r30.u32 ? GuestPtr<const char*>(base, r30.u32) : "(null)";
    const char* type = r31.u32 ? GuestPtr<const char*>(base, r31.u32) : "(null)";
    const char* path = r27.u32 ? GuestPtr<const char*>(base, r27.u32) : "(null)";

    REXLOG_DEBUG("Loading resource: name='{}' type='{}' path='{}'",
        name, type, path);
    REXLOG_DEBUG("  -> handler={:#x}", r3.u32);
}

void Hook_RWS_VtableCall(PPCRegister& r3, PPCRegister& r10) {
    if (!REXCVAR_GET(c2_resource_log))
        return;

    REXLOG_DEBUG("  vtable fn={:#x} on handler={:#x}", r10.u32, r3.u32);
}

void Hook_RWS_ResourceLoaded(PPCRegister& r3) {
    if (!REXCVAR_GET(c2_resource_log))
        return;

    REXLOG_DEBUG("  -> loaded resource={:#x}", r3.u32);
}