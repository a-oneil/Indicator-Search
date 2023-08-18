def b64_add_padding(b64_string):
    b64_string += "=" * ((4 - len(b64_string) % 4) % 4)
    return b64_string
