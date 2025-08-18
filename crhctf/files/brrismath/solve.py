# solver.py
import json
import math
from collections import Counter

def load_l(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data['l']

def try_recover(l_list, min_ord=32, max_ord=126):
    # Convert to ints (they may already be)
    l = [int(x) for x in l_list]
    n = len(l)

    # We'll find a scalar t such that p_i = round(l_i / t) fall inside printable ASCII.
    # Strategy:
    #  - pick one l_j and assume its original ord is one of plausible ASCII values,
    #    compute candidate t = l_j / ord_guess
    #  - apply that t to all l_i and see if rounding gives plausible ordinals
    cand_messages = []
    # choose index list to use for seeds (use first few to speed up)
    seed_indices = range(min(4, n))
    for j in seed_indices:
        lj = l[j]
        # try all plausible target ords for this position
        for ord_guess in range(min_ord, max_ord+1):
            t = lj / ord_guess
            # apply t to all
            recovered = [int(round(x / t)) for x in l]
            # check whether all fall in printable range
            if all(min_ord <= v <= max_ord for v in recovered):
                # map to string
                try:
                    s = ''.join(chr(v) for v in recovered)
                except ValueError:
                    continue
                # score: how many of typical flag chars appear (optional heuristic)
                cand_messages.append((s, t))
    # deduplicate preserving best candidates
    dedup = {}
    for s, t in cand_messages:
        if s not in dedup:
            dedup[s] = t
    # return sorted by length (longer first) or alphabetically
    return list(dedup.items())

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python solver.py out.json")
        sys.exit(1)
    fname = sys.argv[1]
    l_list = load_l(fname)
    candidates = try_recover(l_list, min_ord=32, max_ord=126)
    if not candidates:
        print("No fully-printable ASCII candidate found with simple heuristic.")
        # Try extended ranges for flags (e.g. include curly braces and uppercase/lowercase beyond 126)
        candidates = try_recover(l_list, min_ord=10, max_ord=255)
    print("Candidates (string, scalar t):")
    for s, t in candidates[:30]:
        print(repr(s), "  t=", t)
    if not candidates:
        # fallback: show ratio pattern to help manual inspection
        print("\nFallback: ratios l[i]/l[0]:")
        ratios = [li / l_list[0] for li in l_list]
        for r in ratios:
            print(r)
