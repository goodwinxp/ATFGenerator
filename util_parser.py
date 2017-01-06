import re


def get_pairs_sym(data, sym_open, sym_close):
    positions = []
    for m in re.finditer(sym_open, data):
        positions.append((m.start(), 0))

    for m in re.finditer(sym_close, data):
        positions.append((m.start(), 1))

    positions.sort()

    i = 0
    while True:
        i += 1
        if i >= len(positions):
            break

        (pos, t) = positions[i]
        if t != 1:
            continue

        for j in range(1, i + 1):
            (jpos, jt) = positions[i - j]
            if jt != 0:
                continue

            positions[i - j] = (jpos, 99)
            positions[i] = (pos, 99)

            yield (jpos, pos)
            i = i - j - 1
            break


def get_last_pair_sym(data, sym_open, sym_close):
    pairs = list(get_pairs_sym(data, sym_open, sym_close))
    if len(pairs):
        return pairs[-1]

    return None


def get_first_pair_sym(data, sym_open, sym_close):
    pairs = list(get_pairs_sym(data, sym_open, sym_close))
    if len(pairs):
        return pairs[0]

    return None
