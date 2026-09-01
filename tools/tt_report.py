#!/usr/bin/env python3
"""Report on the TT| time trace left in eMule_Verbose.log by TimeTrace.h.

Usage:  tt_report.py [path/to/eMule_Verbose.log] [--csv out.csv]

Prints, for every event, count / median / p95 / max of each numeric field, and
then a verdict between the two hypotheses:

  A - tick starvation: WM_TIMER is delivered late because the posted messages
      ahead of it saturate the pump, while no single callback is long.
  B - slow callback: the tick is delivered on time but one call inside it holds
      the main thread.

Both are read off the same two numbers: STARVED.gap_ms (how late the 100 ms
timer actually was) and the worst duration measured inside the main thread.
"""

import sys
import os

NOMINAL_TICK_MS = 100           # ::SetTimer(NULL, 0, MSEC(100), UploadTimer)
PUMP_MIN_US = 200               # TT_PUMP_MIN_US in TimeTrace.h: below it PUMP is dropped
BLAME_LINES = 8                 # culprits listed before the tail is folded
STALL_MS = 250                  # a tick this late is a stall, not jitter
NESTED_LOOP_US = 1000000        # a pump call this long is a nested loop, not a stall
# Top level main thread calls. PUMP already contains the dispatch of WM_TIMER,
# hence the whole tick, so summing it with TICK would count the same time twice;
# between two pumps the thread can only be in OnIdle.
BLOCKERS = ("PUMP", "IDLE")
# Finer grained calls, used only to name the culprit inside a stall.
BLAME_DETAIL = ("FLUSH", "SAVEMET", "SETLEN", "TICKUP", "TICKDOWN", "TICKLOG", "RECV", "IDLE")


def read_lines(path):
    """The log is written either as UTF-16LE or as UTF-8, see CLogFile."""
    with open(path, "rb") as f:
        raw = f.read()
    for enc in ("utf-16", "utf-8", "latin-1"):
        try:
            if enc == "utf-16" and not raw.startswith((b"\xff\xfe", b"\xfe\xff")):
                # written without a BOM when the file is appended to
                if raw[1:2] != b"\x00":
                    continue
            return raw.decode(enc, "replace").splitlines()
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", "replace").splitlines()


def parse(lines):
    """-> (records, skipped) with record = (ts_us, tid, event, {key: value})."""
    records = []
    skipped = 0
    for line in lines:
        i = line.find("TT|")
        if i < 0:
            continue
        parts = line[i:].rstrip().split("|")
        if len(parts) < 4:
            skipped += 1
            continue
        try:
            ts = int(parts[1])
            tid = int(parts[2])
        except ValueError:
            skipped += 1
            continue
        event = parts[3]
        fields = {}
        ok = True
        for kv in parts[4:]:
            k, sep, v = kv.partition("=")
            if not sep:
                ok = False
                break
            try:
                fields[k] = int(v, 0)
            except ValueError:
                fields[k] = v
        if not ok:
            skipped += 1
            continue
        records.append((ts, tid, event, fields))
    return records, skipped


def pct(sorted_values, p):
    if not sorted_values:
        return 0
    k = int(round(p / 100.0 * (len(sorted_values) - 1)))
    return sorted_values[k]


def median(sorted_values):
    n = len(sorted_values)
    if not n:
        return 0
    if n % 2:
        return sorted_values[n // 2]
    return (sorted_values[n // 2 - 1] + sorted_values[n // 2]) // 2


def summarize(records):
    """-> {event: (count, {field: sorted values})}"""
    out = {}
    for _, _, event, fields in records:
        count, series = out.setdefault(event, [0, {}])
        out[event][0] = count + 1
        for k, v in fields.items():
            if isinstance(v, int):
                series.setdefault(k, []).append(v)
    for event in out:
        for k in out[event][1]:
            out[event][1][k].sort()
    return out


def main_thread_id(records):
    """The thread that dispatches messages is the main one, by definition."""
    for _, tid, event, _ in records:
        if event in ("PUMP", "STARVED", "IDLE"):
            return tid
    # no pump lines: fall back to the thread that runs the tick
    for _, tid, event, _ in records:
        if event.startswith("TICK"):
            return tid
    return None


def report(records, skipped, path):
    print("file      : %s" % path)
    print("lines     : %d parsed, %d malformed" % (len(records), skipped))
    if not records:
        print("nothing to report - is Verbose + Debug2Disk enabled?")
        return 1
    span_us = records[-1][0] - records[0][0]
    print("span      : %.1f s" % (span_us / 1e6))
    main_tid = main_thread_id(records)
    tids = sorted({r[1] for r in records})
    print("threads   : %s (main: %s)" % (", ".join(str(t) for t in tids), main_tid))
    print()

    stats = summarize(records)
    print("%-10s %8s %-9s %10s %10s %10s %10s" % ("EVENT", "COUNT", "FIELD", "MEDIAN", "P95", "MAX", "SUM"))
    for event in sorted(stats):
        count, series = stats[event]
        if not series:
            print("%-10s %8d %-9s %10s %10s %10s %10s" % (event, count, "-", "", "", "", ""))
            continue
        first = True
        for field in sorted(series):
            values = series[field]
            print("%-10s %8s %-9s %10d %10d %10d %10d" % (
                event if first else "", count if first else "", field,
                median(values), pct(values, 95), values[-1], sum(values)))
            first = False
    print()
    return verdict(records, stats, main_tid)


def verdict(records, stats, main_tid):
    gaps = stats.get("TICKGAP", [0, {}])[1].get("ms", [])
    starved = stats.get("STARVED", [0, {}])[1].get("gap_ms", [])
    posted = stats.get("STARVED", [0, {}])[1].get("posted", [])
    idle_count = stats.get("IDLE", [0, {}])[0]

    print("=== verdict ===")
    if not gaps and not starved:
        print("no TICKGAP and no STARVED lines: the timer never reached the pump,")
        print("or the trace predates the instrumentation. Nothing can be concluded.")
        return 2
    if not gaps:
        print("no TICKGAP lines, falling back on the pump side view (STARVED).")
        print("A nested message loop (a menu, a modal dialog) makes STARVED report")
        print("a gap while the tick itself keeps running, so read this with care.")
        gaps = starved

    for name, series in (("tick gap  (TICKGAP)", gaps), ("pump gap (STARVED)", starved)):
        if series:
            print("%s : median %d ms, p95 %d ms, max %d ms (nominal %d ms)"
                  % (name, median(series), pct(series, 95), series[-1], NOMINAL_TICK_MS))
    if posted:
        print("posted before tick  : median %d, p95 %d, max %d messages"
              % (median(posted), pct(posted, 95), posted[-1]))
    print("IDLE lines          : %d%s" % (idle_count, "  (queue never drains)" if idle_count == 0 else ""))
    rearm = stats.get("RECVREARM", [0, {}])[0]
    if rearm:
        print("RECVREARM           : %d - socket reads pulled into the tick by the limiter" % rearm)
    for ev, (count, series) in sorted(stats.items()):
        if ev == "SUPPR":
            print("suppressed          : %d report lines, %d events dropped by the thresholds"
                  % (count, sum(series.get("n", []))))

    # A pump call that lasts for ever is almost always a nested message loop
    # (TrackPopupMenu, a modal dialog) or the GetMessage that blocks while the
    # application is idle. It is not a stall, and it must not be attributed.
    nested = sorted((f["us"], f.get("msg"), ts) for ts, tid, ev, f in records
                    if ev == "PUMP" and tid == main_tid
                    and isinstance(f.get("us"), int) and f["us"] >= NESTED_LOOP_US)
    if nested:
        print("nested/blocking pump: %d call(s) over %d ms - a nested loop or an idle"
              % (len(nested), NESTED_LOOP_US // 1000))
        for us, msg, ts in nested[-3:][::-1]:
            print("                      t=%.1fs msg=0x%04X %.1f s"
                  % (ts / 1e6, msg or 0, us / 1e6))
        print("                      not counted as a stall, see TimeTrace.h")
    print()

    # A stall is a tick that came in far too late. Each one is classified on
    # its own: the causes coexist in a single trace, and averaging them over the
    # whole run hides the one that matters.
    stalls = _stalls(records, main_tid)
    if not stalls:
        print("VERDICT: neither. No tick came in later than %d ms, so the GUI stall" % STALL_MS)
        print("is not in this trace.")
        return 0

    excess = sum(s[0] for s in stalls)
    klass = {"B": [0, 0.0], "dark": [0, 0.0], "A": [0, 0.0]}
    blame = {}
    for ms, explained, detail, unobserved, longest in stalls:
        if longest >= 0.5 * ms:
            name = "B"
        elif unobserved >= 0.5 * ms:
            name = "dark"
        elif explained >= 0.5 * ms:
            name = "A"
        else:
            name = "A"
        klass[name][0] += 1
        klass[name][1] += ms
        if name == "B":
            for ev, d in detail.items():
                blame.setdefault(ev, [0, 0.0])
                blame[ev][0] += 1
                blame[ev][1] += d

    print("stalls              : %d tick(s) later than %d ms, %.1f s lost in total"
          % (len(stalls), STALL_MS, excess / 1000.0))
    for name, label in (("B", "inside a timed call"),
                        ("dark", "no line from any thread"),
                        ("A", "spread over the pump")):
        n, ms = klass[name]
        if n:
            print("  %-24s %3d stall(s), %5.1f s (%2.0f%%)"
                  % (label, n, ms / 1000.0, 100.0 * ms / excess))
    ranked = sorted(blame.items(), key=lambda kv: -kv[1][1])
    for ev, (n, ms) in ranked[:BLAME_LINES]:
        print("      %-12s %3d x, %6.1f s total, %6.1f ms each" % (ev, n, ms / 1000.0, ms / n))
    if len(ranked) > BLAME_LINES:
        rest = sum(ms for _, (_, ms) in ranked[BLAME_LINES:])
        print("      %-12s %3d more, %5.1f s total" % ("...", len(ranked) - BLAME_LINES, rest / 1000.0))
    print()

    top = max(klass.items(), key=lambda kv: kv[1][1])
    mixed = [k for k, v in klass.items() if v[1] >= 0.25 * excess and k != top[0]]
    if top[0] == "B":
        worst = max(blame.items(), key=lambda kv: kv[1][1])[0] if blame else "?"
        print("VERDICT: B - slow callback.")
        print("The tick is on time except for %d stalls, and the largest share of the"
              % len(stalls))
        print("time they lose is inside main thread calls the trace timed, %s first." % worst)
        print("Look at that call, not at the pump.")
    elif top[0] == "dark":
        print("VERDICT: neither A nor B - the process is not running.")
        print("The largest share of the time lost in the %d stalls falls in windows"
              % len(stalls))
        print("where no thread wrote a single line: not the pump (nothing was")
        print("dispatched) and not a callback (none was on the stack). Look outside")
        print("the message loop - host scheduling, paging, the filesystem.")
    else:
        print("VERDICT: A - tick starvation.")
        print("In most of the %d stalls no single main thread call explains the delay"
              % len(stalls))
        print("and the thread kept dispatching: the messages posted ahead of WM_TIMER")
        print("(p95 %d, max %d per tick) are what keeps the pump busy; %s corroborates."
              % (pct(posted, 95) if posted else 0, posted[-1] if posted else 0,
                 "the absence of IDLE lines" if idle_count == 0 else "the %d IDLE lines" % idle_count))
    if mixed:
        print()
        print("The trace is not single-cause: %s also account%s for a quarter or more"
              % (" and ".join(sorted(mixed)), "" if len(mixed) > 1 else "s"))
        print("of the time lost. Both have to be dealt with.")
    return 0


def _posted_near(posted_at, ts):
    """The message count the tick closing this window reported."""
    best, dist = 0, None
    for at, posted in posted_at:
        d = abs(at - ts)
        if dist is None or d < dist:
            best, dist = posted, d
        elif at > ts:
            break
    return best


def _name(event, fields):
    """A pump line is only worth naming together with the message it dispatched."""
    if event == "PUMP" and isinstance(fields.get("msg"), int):
        return "PUMP 0x%04X" % fields["msg"]
    return event


def _clip(begin, end, lo, hi):
    """Milliseconds of [begin, end] that fall inside the stall window.

    A call that started just before the window still holds the thread inside
    it, so the two intervals are intersected instead of requiring containment.
    """
    return max(0, min(end, hi) - max(begin, lo)) / 1000.0


def _stalls(records, main_tid):
    """Every late tick, with the main thread work that ended inside its window.

    Returns (excess_ms, explained_ms, {event: ms}, unobserved_ms, longest_ms)
    per stall; longest_ms is the single longest call, which is what separates one
    slow callback from a pump kept busy by a crowd of short dispatches.
    Only BLOCKERS are summed: they are the top level calls of the main thread,
    so a tick and the flush inside it are never counted twice. unobserved_ms is
    the part of the window in which no thread of the process wrote a line at
    all - neither a callback nor the pump was running, and the trace cannot say
    where the time went.
    """
    seen = sorted((ts - f["us"] if isinstance(f.get("us"), int) else ts, ts)
                  for ts, tid, ev, f in records)
    # PUMP is dropped below TT_PUMP_MIN_US, so a window can look empty while the
    # thread was in fact dispatching a crowd of short messages. The tick counts
    # them all, and that count bounds how much time they can possibly hide.
    posted_at = sorted((ts, f["posted"]) for ts, tid, ev, f in records
                       if ev == "STARVED" and tid == main_tid
                       and isinstance(f.get("posted"), int))
    work = [(ts - f["us"], ts, _name(ev, f), f["us"]) for ts, tid, ev, f in records
            if ev in BLOCKERS and tid == main_tid and isinstance(f.get("us"), int)
            and f["us"] < NESTED_LOOP_US]
    work.sort()
    detailed = [(ts - f["us"], ts, ev, f["us"]) for ts, tid, ev, f in records
                if ev in BLAME_DETAIL and tid == main_tid and isinstance(f.get("us"), int)]
    detailed.sort()

    out = []
    for ts, tid, ev, f in records:
        if ev != "TICKGAP" or tid != main_tid or not isinstance(f.get("ms"), int):
            continue
        if f["ms"] < STALL_MS:
            continue
        lo = ts - f["ms"] * 1000
        excess = f["ms"] - NOMINAL_TICK_MS
        inside = [(name, _clip(b, e, lo, ts)) for b, e, name, us in work]
        explained = sum(ms for _, ms in inside)
        longest = max([ms for _, ms in inside] or [0.0])
        detail = {}
        for b, e, name, us in detailed:
            ms = _clip(b, e, lo, ts)
            if ms >= 0.1 * excess:
                detail[name] = detail.get(name, 0.0) + ms
        if not detail:
            for name, ms in inside:
                if ms > 0.0:
                    detail[name] = detail.get(name, 0.0) + ms
        hidden = _posted_near(posted_at, ts) * PUMP_MIN_US / 1000.0
        dark = max(0.0, _unobserved(seen, lo, ts) - hidden)
        out.append((float(excess), min(explained, float(excess)), detail, dark, longest))
    return out


def _unobserved(seen, lo, hi):
    """Milliseconds of [lo, hi] not covered by any line from any thread."""
    covered = 0
    reach = lo
    for begin, end in seen:
        if end <= lo:
            continue
        if begin >= hi:
            break
        begin = max(begin, reach, lo)
        end = min(end, hi)
        if end > begin:
            covered += end - begin
            reach = end
    return max(0, (hi - lo) - covered) / 1000.0


def main(argv):
    path = None
    csv_out = None
    i = 1
    while i < len(argv):
        if argv[i] == "--csv" and i + 1 < len(argv):
            csv_out = argv[i + 1]
            i += 2
            continue
        path = argv[i]
        i += 1
    if path is None:
        path = "eMule_Verbose.log"
    if not os.path.isfile(path):
        sys.stderr.write("not a file: %s\n" % path)
        return 2
    records, skipped = parse(read_lines(path))
    if csv_out:
        with open(csv_out, "w") as f:
            f.write("ts_us,tid,event,fields\n")
            for ts, tid, event, fields in records:
                f.write("%d,%d,%s,%s\n" % (ts, tid, event,
                        " ".join("%s=%s" % kv for kv in sorted(fields.items()))))
        print("wrote %s" % csv_out)
    return report(records, skipped, path)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
