#!/usr/bin/env python3
"""Summarise a --c2_perf_csv frame log: rolling 5 s windows with avg/1%-low FPS and counters."""
import csv, sys, statistics
rows = list(csv.DictReader(open(sys.argv[1])))
win_s = float(sys.argv[2]) if len(sys.argv) > 2 else 5.0
t = 0.0; win = []; wstart = 0.0
def flush(win, wstart, wend):
    ft = sorted(float(r['frame_time_us']) for r in win if float(r['frame_time_us']) > 0)
    if not ft: return
    avg = 1e6 / statistics.mean(ft)
    low = 1e6 / ft[int(len(ft) * 0.99)] if len(ft) > 1 else avg
    draws = statistics.mean(float(r['draw_calls']) for r in win)
    stalls = sum(float(r['command_buffer_stalls']) for r in win)
    texm = sum(float(r['texture_cache_misses']) for r in win)
    pipm = sum(float(r['pipeline_cache_misses']) for r in win)
    print(f"{wstart:7.1f}-{wend:6.1f}s  frames {len(ft):4d}  avg {avg:6.1f} fps  1%low {low:6.1f}  draws/frame {draws:7.0f}  stalls {stalls:5.0f}  texmiss {texm:5.0f}  pipemiss {pipm:4.0f}")
for r in rows:
    dt = float(r['frame_time_us']) / 1e6
    t += dt; win.append(r)
    if t - wstart >= win_s:
        flush(win, wstart, t); win = []; wstart = t
flush(win, wstart, t)
print(f"total {t:.1f}s, {len(rows)} frames")
