def decode_ida_id(ida_id):
    normal_id = 0
    for c in ida_id:
        normal_id *= 0x40
        normal_id += (ord(c) & 0x7f)

    normal_id -= 0x40
    return normal_id
