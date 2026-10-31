// tracy-sampdump: text dump of a Tracy capture taken from the game with --c2_profile.
// Prints call-stack sampling statistics (top symbols by exclusive samples,
// per thread) and zone statistics per thread from a .tracy capture.
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <vector>

#include "server/TracyFileRead.hpp"
#include "server/TracyWorker.hpp"

int main(int argc, char** argv) {
  if (argc < 2) { fprintf(stderr, "usage: %s file.tracy [topN]\n", argv[0]); return 1; }
  int topN = argc > 2 ? atoi(argv[2]) : 60;
  auto f = std::unique_ptr<tracy::FileRead>(tracy::FileRead::Open(argv[1]));
  if (!f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }
  tracy::Worker worker(*f, tracy::EventType::All, true, false);
  while (!worker.AreSourceLocationZonesReady()) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  while (!worker.AreSymbolSamplesReady()) std::this_thread::sleep_for(std::chrono::milliseconds(50));

  printf("capture: %s\n", worker.GetCaptureName().c_str());
  printf("duration: %.2f s, sampling period %.1f us, samples %llu, frames %llu\n",
         worker.GetLastTime() / 1e9, worker.GetSamplingPeriod() / 1e3,
         (unsigned long long)worker.GetCallstackSampleCount(),
         (unsigned long long)worker.GetFrameCount(*worker.GetFramesBase()));

  // Per-thread sample counts.
  printf("\n== threads (sample counts) ==\n");
  struct TS { uint64_t id; const char* name; size_t samples; size_t zones; };
  std::vector<TS> ts;
  for (const auto* td : worker.GetThreadData()) {
    ts.push_back({td->id, worker.GetThreadName(td->id), td->samples.size(), td->count});
  }
  std::sort(ts.begin(), ts.end(), [](const TS& a, const TS& b) { return a.samples > b.samples; });
  for (const auto& t : ts) {
    if (t.samples == 0 && t.zones == 0) continue;
    printf("  tid %-8llu %-40s samples %-8zu zones %zu\n", (unsigned long long)t.id, t.name, t.samples, t.zones);
  }

  // Global symbol statistics.
  printf("\n== top %d symbols by exclusive samples (all threads) ==\n", topN);
  struct SS { uint64_t addr; uint32_t excl, incl; };
  std::vector<SS> ss;
  uint64_t total_excl = 0;
  for (const auto& [addr, st] : worker.GetSymbolStats()) { ss.push_back({addr, st.excl, st.incl}); total_excl += st.excl; }
  std::sort(ss.begin(), ss.end(), [](const SS& a, const SS& b) { return a.excl > b.excl; });
  auto symname = [&](uint64_t addr) -> std::string {
    const auto* sd = worker.GetSymbolData(addr);
    if (!sd) return "?";
    std::string n = worker.GetString(sd->name);
    std::string img = worker.GetString(sd->imageName);
    size_t slash = img.find_last_of("/\\");
    if (slash != std::string::npos) img = img.substr(slash + 1);
    return img + "!" + n;
  };
  int shown = 0;
  for (const auto& s : ss) {
    if (shown++ >= topN) break;
    printf("  %6.2f%% excl %-8u incl %-8u %s\n", total_excl ? 100.0 * s.excl / total_excl : 0.0, s.excl, s.incl, symname(s.addr).c_str());
  }

  // Per-thread exclusive symbol stats from raw samples (top of stack).
  printf("\n== per-thread top symbols (leaf frame of each sample) ==\n");
  for (const auto& t : ts) {
    if (t.samples < 200) continue;
    const auto* td = worker.GetThreadData(t.id);
    std::unordered_map<uint64_t, uint32_t> leaf;
    for (const auto& s : td->samples) {
      const auto& cs = worker.GetCallstack(s.callstack.Val());
      if (cs.empty()) continue;
      const auto* frame = worker.GetCallstackFrame(cs[0]);
      if (!frame) continue;
      leaf[frame->data[0].symAddr]++;
    }
    std::vector<std::pair<uint64_t, uint32_t>> v(leaf.begin(), leaf.end());
    std::sort(v.begin(), v.end(), [](auto& a, auto& b) { return a.second > b.second; });
    printf("\n-- tid %llu %s (%zu samples)\n", (unsigned long long)t.id, t.name, t.samples);
    int n = 0;
    for (auto& [addr, cnt] : v) {
      if (n++ >= 25) break;
      printf("  %6.2f%% %-8u %s\n", 100.0 * cnt / t.samples, cnt, symname(addr).c_str());
    }
  }


  // Per-thread inclusive symbol stats (symbol appears anywhere in the sampled stack).
  printf("\n== per-thread inclusive top symbols (any frame of each sample) ==\n");
  for (const auto& t : ts) {
    if (t.samples < 20000) continue;
    const auto* td = worker.GetThreadData(t.id);
    std::unordered_map<uint64_t, uint32_t> incl;
    for (const auto& s : td->samples) {
      const auto& cs = worker.GetCallstack(s.callstack.Val());
      std::vector<uint64_t> seen;
      for (size_t i = 0; i < cs.size() && i < 40; i++) {
        const auto* frame = worker.GetCallstackFrame(cs[i]);
        if (!frame) continue;
        for (uint8_t k = 0; k < frame->size; k++) {
          uint64_t a = frame->data[k].symAddr;
          if (std::find(seen.begin(), seen.end(), a) == seen.end()) { seen.push_back(a); incl[a]++; }
        }
      }
    }
    std::vector<std::pair<uint64_t, uint32_t>> v(incl.begin(), incl.end());
    std::sort(v.begin(), v.end(), [](auto& a, auto& b) { return a.second > b.second; });
    printf("\n-- tid %llu %s (%zu samples)\n", (unsigned long long)t.id, t.name, t.samples);
    int n = 0;
    for (auto& [addr, cnt] : v) {
      if (n++ >= 60) break;
      printf("  %6.2f%% %-8u %s\n", 100.0 * cnt / t.samples, cnt, symname(addr).c_str());
    }
  }

  // Zone statistics (total time per source location).
  printf("\n== zones by total time ==\n");
  struct ZS { std::string name; int64_t total; uint64_t count; };
  std::vector<ZS> zs;
  for (const auto& [srcloc, zones] : worker.GetSourceLocationZones()) {
    const auto& sl = worker.GetSourceLocation(srcloc);
    std::string nm = worker.GetString(sl.name.active ? sl.name : sl.function);
    std::string file = worker.GetString(sl.file);
    size_t slash = file.find_last_of("/\\");
    if (slash != std::string::npos) file = file.substr(slash + 1);
    nm += " [" + file + ":" + std::to_string(sl.line) + "]";
    zs.push_back({nm, zones.total, (uint64_t)zones.zones.size()});
  }
  std::sort(zs.begin(), zs.end(), [](const ZS& a, const ZS& b) { return a.total > b.total; });
  int zn = 0;
  for (const auto& z : zs) {
    if (zn++ >= topN) break;
    printf("  %10.3f ms total  %8llu calls  %10.1f us avg  %s\n", z.total / 1e6, (unsigned long long)z.count,
           z.count ? z.total / 1e3 / z.count : 0.0, z.name.c_str());
  }
  return 0;
}
