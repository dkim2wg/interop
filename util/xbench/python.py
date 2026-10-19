import sys, json, time
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'python'))
from dkim2verify import verify_message
lst, dnsf, reps = sys.argv[1], sys.argv[2], int(sys.argv[3])
dns = json.load(open(dnsf))
msgs = [open(p.strip(), 'rb').read() for p in open(lst) if p.strip()]
for walk in ('plan', 'undo'):
    best = 9e9
    for _ in range(reps):
        v = {}; t = time.perf_counter()
        for raw in msgs:
            r = verify_message(raw, dns, full_chain=True, skip_timestamp_check=True, walk=walk)
            v[r.status] = v.get(r.status, 0) + 1
        best = min(best, time.perf_counter() - t)
    print('python %s %.3f %s' % (walk, best, ','.join('%s=%d' % kv for kv in sorted(v.items()))))
