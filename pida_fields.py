def decode_name_fields(ida_fields):
    i = -1
    stop = len(ida_fields)
    while True:
        i += 1
        if i == stop:
            break

        count = ord(ida_fields[i]) - 1
        if count == 0:
            continue

        i += 1
        yield ida_fields[i:i + count]
        i += count - 1
