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

void LogLoadResourceArgs(PPCRegister& r3, PPCRegister& r4, PPCRegister& r5,
    PPCRegister& r6, PPCRegister& r7, PPCRegister& r8) {

    if (!REXCVAR_GET(c2_resource_log))
        return;

    uint8_t* base = rex::system::kernel_state()->memory()->virtual_membase();

    auto pStrName = rex::memory::GuestPtr<const char*>(base, r3.u32);
    auto pResId = rex::memory::GuestPtr<const char*>(base, r4.u32);
    auto pStrType = rex::memory::GuestPtr<const char*>(base, r5.u32);
    auto pResourcePath = rex::memory::GuestPtr<const char*>(base, r6.u32);

    REXLOG_DEBUG(
        "RWS::LoadResource: Loading Resource: pStrName='{}' pResId={:#x} (guid[0]={:#x}) pStrType='{}' "
        "pResourcePath='{}' pStream={:#x} uiStreamSize={}",
        pStrName ? pStrName : "(null)", r4.u32,
        pResId ? *pResId : 0,
        pStrType ? pStrType : "(null)",
        pResourcePath ? pResourcePath : "(null)", r7.u32, r8.u32);
}

void LogHandlerFound(PPCRegister& r3, PPCRegister& r30) {

	if (!REXCVAR_GET(c2_resource_log))
        return;

    uint8_t* base = rex::system::kernel_state()->memory()->virtual_membase();
    auto pStrName = rex::memory::GuestPtr<const char*>(base, r30.u32);

    if (r3.u32 != 0) {
        REXLOG_DEBUG("RWS::LoadResource: Handler for '{}' found: {:#x}", pStrName ? pStrName : "(null)", r3.u32);
    }
    else {
        REXLOG_DEBUG("RWS::LoadResource: Handler for '{}' NOT found. Ignoring Resource.", pStrName ? pStrName : "(null)");
    }
}

void LogUsingStreaming(PPCRegister& r30) {

    if (!REXCVAR_GET(c2_resource_log))
        return;

    uint8_t* base = rex::system::kernel_state()->memory()->virtual_membase();
    auto pStrName = rex::memory::GuestPtr<const char*>(base, r30.u32);

	REXLOG_DEBUG("RWS::LoadResource: Loading '{}' as a streaming resource.", pStrName ? pStrName : "(null)");
}

void LogCustomResourceHandler(PPCRegister& r30, PPCRegister& ctr) {

    if (!REXCVAR_GET(c2_resource_log))
        return;

    uint8_t* base = rex::system::kernel_state()->memory()->virtual_membase();
    const char* pStrName = rex::memory::GuestPtr<const char*>(base, r30.u32);
    REXLOG_DEBUG("RWS::LoadResource: Custom resource loading function is being used for '{}', address of the function is: 0x{:08X}",
        pStrName ? pStrName : "(null)", ctr.u32);
}

void LogResourceAddCheck(PPCRegister& r30, PPCRegister& r29) {

    if (!REXCVAR_GET(c2_resource_log))
        return;

    if (r29.u32 == 0) {
        return;  // Add is not called when the vtable load returned null  
    }

    uint8_t* base = rex::system::kernel_state()->memory()->virtual_membase();
    auto pStrName = rex::memory::GuestPtr<const char*>(base, r30.u32);

    REXLOG_DEBUG("RWS::LoadResource: RWS::CResourceManager::Add will be called for '{}'", pStrName ? pStrName : "(null)");
}