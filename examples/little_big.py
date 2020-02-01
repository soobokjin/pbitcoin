# python bytes literals: https://docs.python.org/3/reference/lexical_analysis.html#grammar-token-shortbyteschar

number: int = 500

big_n: bytes = number.to_bytes(2, 'big')
little_n: bytes = number.to_bytes(2, 'little')

assert big_n[1] == little_n[0]
assert little_n[0] == big_n[1]

print(f"big: {big_n} little: {little_n}")
