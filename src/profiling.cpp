// crackdown2 - optional profiling aids.
//
// The rexglue SDK compiles Tracy zones and a per-frame perf-counter registry
// into every non-Release build (REXGLUE_ENABLE_PROFILING /
// REXGLUE_ENABLE_PERF_COUNTERS come from the SDK's CMake interface), but the
// runtime never starts the Tracy listener and never opens the counter CSV.
// These two cvars expose both so a RelWithDebInfo build can be profiled with
// stock Tracy tools (tracy-capture / Tracy.exe on port 8086) and frame times
// can be logged without screenshots. Both are no-ops in Release builds.

#include "profiling.h"

#include <rex/cvar.h>
#include <rex/logging.h>
#include <rex/perf/counter.h>

#include <string>

#if defined(__linux__) || defined(__ANDROID__)
#include <dirent.h>
#include <dlfcn.h>
#include <signal.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <map>
#include <thread>
#include <vector>
#endif

REXCVAR_DEFINE_INT32(c2_cpu_sample_after, 0, "Debug",
                     "Linux/Android: start a signal-based CPU sampler this many seconds after launch "
                     "(0 = off). Writes per-thread hot code addresses to c2_cpu_sample_out.");
REXCVAR_DEFINE_INT32(c2_cpu_sample_seconds, 15, "Debug", "Length of the CPU sampler run in seconds.");
REXCVAR_DEFINE_STRING(c2_cpu_sample_trigger, "", "Debug",
                      "Linux/Android: path of a trigger file; whenever it appears the CPU sampler "
                      "deletes it and runs once (alternative to c2_cpu_sample_after).");
REXCVAR_DEFINE_STRING(c2_cpu_sample_out, "", "Debug",
                      "Output file for the CPU sampler (default: cpu_samples.txt beside the log).");
REXCVAR_DECLARE(std::string, log_file);

REXCVAR_DEFINE_BOOL(c2_profile, false, "Debug",
                    "Start the SDK's built-in Tracy profiler listener (TCP 8086) so tracy-capture or the "
                    "Tracy UI can attach. Debug/RelWithDebInfo builds only.");
REXCVAR_DEFINE_STRING(c2_perf_csv, "", "Debug",
                      "Write the SDK's per-frame perf counters (frame time, draw calls, command buffer "
                      "stalls, texture/pipeline cache hits) to this CSV file. Debug/RelWithDebInfo builds only.");

namespace c2 {

#if defined(__linux__) || defined(__ANDROID__)
namespace {

// Lock-free ring filled from the signal handler.
constexpr int kStackDepth = 12;
struct CpuSample {
  uint32_t tid;
  uintptr_t pc;
  uintptr_t frames[kStackDepth];  // return addresses from the frame-pointer chain
};
constexpr size_t kMaxSamples = 1 << 17;
CpuSample* g_samples = nullptr;
std::atomic<size_t> g_sample_count{0};

void CpuSampleHandler(int, siginfo_t*, void* context) {
  size_t i = g_sample_count.fetch_add(1, std::memory_order_relaxed);
  if (i >= kMaxSamples) {
    return;
  }
  auto* uc = static_cast<ucontext_t*>(context);
#if defined(__aarch64__)
  uintptr_t pc = uc->uc_mcontext.pc;
#elif defined(__x86_64__)
  uintptr_t pc = uc->uc_mcontext.gregs[REG_RIP];
#else
  uintptr_t pc = 0;
#endif
  CpuSample& sample = g_samples[i];
  sample.tid = uint32_t(syscall(SYS_gettid));
  sample.pc = pc;
#if defined(__aarch64__)
  uintptr_t fp = uc->uc_mcontext.regs[29];
  uintptr_t lr = uc->uc_mcontext.regs[30];
  int depth = 0;
  sample.frames[depth++] = lr;
  // Walk the AArch64 frame record chain: [fp] = previous fp, [fp + 8] = return address.
  for (; depth < kStackDepth && fp && (fp & 7) == 0; ++depth) {
    const uintptr_t* record = reinterpret_cast<const uintptr_t*>(fp);
    uintptr_t next_fp = record[0];
    sample.frames[depth] = record[1];
    if (next_fp <= fp || next_fp - fp > (1u << 20)) {
      ++depth;
      break;
    }
    fp = next_fp;
  }
  for (; depth < kStackDepth; ++depth) {
    sample.frames[depth] = 0;
  }
#else
  for (int d = 0; d < kStackDepth; ++d) {
    sample.frames[d] = 0;
  }
#endif
}

std::string ReadSmallFile(const std::string& path) {
  std::ifstream f(path);
  std::string s;
  std::getline(f, s, '\0');
  return s;
}

// Whether a thread is currently runnable (state R in /proc/self/task/<tid>/stat).
bool ThreadIsRunning(const std::string& tid) {
  std::string stat = ReadSmallFile("/proc/self/task/" + tid + "/stat");
  size_t close = stat.rfind(')');
  return close != std::string::npos && close + 2 < stat.size() && stat[close + 2] == 'R';
}

void RunCpuSampler(int after_s, int duration_s, std::string out_path) {
  std::this_thread::sleep_for(std::chrono::seconds(after_s));
  if (!g_samples) {
    g_samples = new CpuSample[kMaxSamples];
  }
  g_sample_count = 0;
  struct sigaction sa = {};
  sa.sa_sigaction = CpuSampleHandler;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGPROF, &sa, nullptr);
  const pid_t pid = getpid();
  const pid_t self_tid = pid_t(syscall(SYS_gettid));
  REXLOG_INFO("cpu sampler: sampling for {} s -> {}", duration_s, out_path);
  std::map<uint32_t, uint64_t> ticks_seen;  // tid -> times it was running at a tick
  uint64_t ticks = 0;
  auto end = std::chrono::steady_clock::now() + std::chrono::seconds(duration_s);
  while (std::chrono::steady_clock::now() < end) {
    // ~500 Hz per running thread.
    if (DIR* d = opendir("/proc/self/task")) {
      while (dirent* e = readdir(d)) {
        if (e->d_name[0] == '.') {
          continue;
        }
        pid_t tid = pid_t(atoi(e->d_name));
        if (tid == self_tid || !ThreadIsRunning(e->d_name)) {
          continue;
        }
        ++ticks_seen[uint32_t(tid)];
        syscall(SYS_tgkill, pid, tid, SIGPROF);
      }
      closedir(d);
    }
    ++ticks;
    std::this_thread::sleep_for(std::chrono::microseconds(2000));
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  signal(SIGPROF, SIG_IGN);
  size_t n = std::min(g_sample_count.load(), kMaxSamples);

  // Aggregate: per thread, per module offset.
  std::map<uint32_t, std::map<std::pair<std::string, uintptr_t>, uint64_t>> per_thread;
  // Per thread: (first runtime frame, first game frame) -> count.
  std::map<uint32_t, std::map<std::pair<uintptr_t, uintptr_t>, uint64_t>> per_thread_callers;
  auto module_offset = [](uintptr_t addr, std::string& module_out) -> uintptr_t {
    Dl_info info = {};
    if (!addr || !dladdr(reinterpret_cast<void*>(addr), &info) || !info.dli_fname) {
      module_out = "?";
      return addr;
    }
    module_out = info.dli_fname;
    size_t slash = module_out.rfind('/');
    if (slash != std::string::npos) {
      module_out = module_out.substr(slash + 1);
    }
    return addr - reinterpret_cast<uintptr_t>(info.dli_fbase);
  };
  std::map<uint32_t, uint64_t> per_thread_total;
  for (size_t i = 0; i < n; ++i) {
    Dl_info info = {};
    std::string module = "?";
    uintptr_t offset = g_samples[i].pc;
    if (dladdr(reinterpret_cast<void*>(g_samples[i].pc), &info) && info.dli_fname) {
      module = info.dli_fname;
      size_t slash = module.rfind('/');
      if (slash != std::string::npos) {
        module = module.substr(slash + 1);
      }
      offset = g_samples[i].pc - reinterpret_cast<uintptr_t>(info.dli_fbase);
    }
    ++per_thread[g_samples[i].tid][{module, offset}];
    uintptr_t runtime_frame = 0, game_frame = 0;
    std::string frame_module;
    for (int d = -1; d < kStackDepth && !(runtime_frame && game_frame); ++d) {
      uintptr_t addr = d < 0 ? g_samples[i].pc : g_samples[i].frames[d];
      if (!addr) {
        continue;
      }
      uintptr_t frame_offset = module_offset(addr, frame_module);
      if (!runtime_frame && frame_module == "librexruntime.so") {
        runtime_frame = frame_offset;
      } else if (!game_frame && frame_module == "libmain.so") {
        game_frame = frame_offset;
      }
    }
    ++per_thread_callers[g_samples[i].tid][{runtime_frame, game_frame}];
    ++per_thread_total[g_samples[i].tid];
  }
  FILE* f = std::fopen(out_path.c_str(), "w");
  if (!f) {
    REXLOG_ERROR("cpu sampler: cannot write {}", out_path);
    return;
  }
  std::fprintf(f, "# ticks %llu, samples %zu, duration %d s\n", (unsigned long long)ticks, n,
               duration_s);
  std::vector<std::pair<uint64_t, uint32_t>> threads;
  for (auto& [tid, total] : per_thread_total) {
    threads.push_back({total, tid});
  }
  std::sort(threads.rbegin(), threads.rend());
  for (auto& [total, tid] : threads) {
    std::string name = ReadSmallFile("/proc/self/task/" + std::to_string(tid) + "/comm");
    while (!name.empty() && (name.back() == '\n' || name.back() == '\0')) {
      name.pop_back();
    }
    std::fprintf(f, "thread %u %s samples %llu running_ticks %llu\n", tid, name.c_str(),
                 (unsigned long long)total, (unsigned long long)ticks_seen[tid]);
    std::vector<std::pair<uint64_t, std::pair<std::string, uintptr_t>>> hot;
    for (auto& [key, count] : per_thread[tid]) {
      hot.push_back({count, key});
    }
    std::sort(hot.rbegin(), hot.rend());
    for (size_t i = 0; i < hot.size() && i < 100000; ++i) {
      std::fprintf(f, "  %llu %s 0x%zx\n", (unsigned long long)hot[i].first,
                   hot[i].second.first.c_str(), size_t(hot[i].second.second));
    }
    std::vector<std::pair<uint64_t, std::pair<uintptr_t, uintptr_t>>> callers;
    for (auto& [key, count] : per_thread_callers[tid]) {
      callers.push_back({count, key});
    }
    std::sort(callers.rbegin(), callers.rend());
    for (size_t i = 0; i < callers.size() && i < 15; ++i) {
      std::fprintf(f, "  caller %llu runtime 0x%zx game 0x%zx\n",
                   (unsigned long long)callers[i].first, size_t(callers[i].second.first),
                   size_t(callers[i].second.second));
    }
  }
  std::fclose(f);
  REXLOG_INFO("cpu sampler: wrote {} samples from {} threads to {}", n, threads.size(), out_path);
}

}  // namespace
#endif

void StartProfilingIfRequested() {
#if defined(__linux__) || defined(__ANDROID__)
  if (!REXCVAR_GET(c2_cpu_sample_trigger).empty()) {
    std::string trigger = REXCVAR_GET(c2_cpu_sample_trigger);
    std::string out = REXCVAR_GET(c2_cpu_sample_out);
    if (out.empty()) {
      out = trigger + ".txt";
    }
    int duration = int(REXCVAR_GET(c2_cpu_sample_seconds));
    std::thread([trigger, out, duration]() {
      for (;;) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        if (access(trigger.c_str(), F_OK) == 0) {
          unlink(trigger.c_str());
          RunCpuSampler(0, duration, out);
        }
      }
    }).detach();
  }
  if (REXCVAR_GET(c2_cpu_sample_after) > 0) {
    std::string out = REXCVAR_GET(c2_cpu_sample_out);
    if (out.empty()) {
      std::string log = REXCVAR_GET(log_file);
      size_t slash = log.rfind('/');
      out = (slash != std::string::npos ? log.substr(0, slash + 1) : std::string()) +
            "cpu_samples.txt";
    }
    std::thread(RunCpuSampler, int(REXCVAR_GET(c2_cpu_sample_after)),
                int(REXCVAR_GET(c2_cpu_sample_seconds)), out)
        .detach();
  }
#endif
  if (REXCVAR_GET(c2_profile)) {
#ifdef REXGLUE_ENABLE_PROFILING
    rex::perf::Profiler::Startup();
    REXLOG_INFO("profiling: Tracy listener started (--c2_profile)");
#else
    REXLOG_WARN("profiling: --c2_profile has no effect in a Release build");
#endif
  }
  const std::string csv = REXCVAR_GET(c2_perf_csv);
  if (!csv.empty()) {
#ifdef REXGLUE_ENABLE_PERF_COUNTERS
    rex::perf::SetCsvLogPath(csv);
    REXLOG_INFO("profiling: per-frame perf counters -> {}", csv);
#else
    REXLOG_WARN("profiling: --c2_perf_csv has no effect in a Release build");
#endif
  }
}

}  // namespace c2
