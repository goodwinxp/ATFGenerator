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


def encode_name_fields(fields):
    ida_fields = []
    for field in fields:
        count = len(field)
        assert count in range(0, 254), 'So much length field. [0, 254]'

        ida_fields.append(chr(count + 1))
        ida_fields.append(field)

    return ''.join(ida_fields)
