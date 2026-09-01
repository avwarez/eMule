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
GAP_ALERT_MS = 1.5 * NOMINAL_TICK_MS
# Events measured on the main thread whose 'us' is a callback duration.
MAIN_THREAD_DURATIONS = ("TICK", "TICKUP", "TICKDOWN", "TICKLOG", "FLUSH", "SAVEMET", "SETLEN", "PUMP", "RECV", "IDLE")


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
    gaps = stats.get("STARVED", [0, {}])[1].get("gap_ms", [])
    posted = stats.get("STARVED", [0, {}])[1].get("posted", [])
    idle_count = stats.get("IDLE", [0, {}])[0]

    worst_event, worst_ms = None, 0.0
    for event in MAIN_THREAD_DURATIONS:
        if event not in stats:
            continue
        us = stats[event][1].get("us", [])
        if not us:
            continue
        # only durations measured on the main thread can hold the pump
        on_main = [u for ts, tid, ev, f in records
                   if ev == event and tid == main_tid and isinstance(f.get("us"), int)
                   for u in (f["us"],)]
        if not on_main:
            continue
        m = max(on_main) / 1000.0
        if m > worst_ms:
            worst_event, worst_ms = event, m

    print("=== verdict ===")
    if not gaps:
        print("no STARVED lines: the timer never reached the pump, or the trace")
        print("predates the instrumentation. Nothing can be concluded.")
        return 2

    gap_p95 = pct(gaps, 95)
    gap_max = gaps[-1]
    print("tick gap        : median %d ms, p95 %d ms, max %d ms (nominal %d ms)"
          % (median(gaps), gap_p95, gap_max, NOMINAL_TICK_MS))
    if posted:
        print("posted before   : median %d, p95 %d, max %d messages per tick"
              % (median(posted), pct(posted, 95), posted[-1]))
    print("worst main call : %s %.1f ms" % (worst_event or "-", worst_ms))
    print("IDLE lines      : %d%s" % (idle_count, "  (queue never drains)" if idle_count == 0 else ""))
    rearm = stats.get("RECVREARM", [0, {}])[0]
    if rearm:
        print("RECVREARM       : %d - socket reads pulled into the tick by the limiter" % rearm)
    for ev, (count, series) in sorted(stats.items()):
        if ev == "SUPPR":
            print("suppressed      : %d report lines, %d events dropped by the thresholds"
                  % (count, sum(series.get("n", []))))
    print()

    if gap_p95 <= GAP_ALERT_MS:
        print("VERDICT: neither. The 100 ms tick is being delivered on time")
        print("(p95 %d ms <= %d ms), so the GUI stall is not in this trace." % (gap_p95, GAP_ALERT_MS))
        return 0
    if worst_ms >= 0.5 * gap_p95:
        print("VERDICT: B - slow callback.")
        print("The tick is late (p95 %d ms) but a single main thread call accounts" % gap_p95)
        print("for most of it (%s, %.1f ms). Look at that call, not at the pump." % (worst_event, worst_ms))
        return 0
    print("VERDICT: A - tick starvation.")
    print("The tick is late (p95 %d ms) and no single main thread call explains it" % gap_p95)
    print("(worst is %s at %.1f ms). The dispatch of the posted messages ahead of" % (worst_event or "-", worst_ms))
    print("WM_TIMER is what keeps the pump busy; %s corroborates."
          % ("the absence of IDLE lines" if idle_count == 0 else "the %d IDLE lines" % idle_count))
    return 0


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
