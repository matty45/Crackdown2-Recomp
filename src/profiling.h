// crackdown2 - optional profiling aids (see profiling.cpp).
#pragma once

namespace c2 {

// Honour --c2_profile / --c2_perf_csv. Call once early (OnPreSetup).
void StartProfilingIfRequested();

}  // namespace c2
