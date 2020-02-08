from pbitcoin.constant import N
from pbitcoin.ecc.private_key import PrivateKey, Signature

z = 12345
p1 = PrivateKey(1234567)
sig = p1.sign(z)
minus_sig = Signature(sig.r, -sig.s % N)

print(sig)
print(p1.pub_k.verify(z, sig))
print(minus_sig)
print(p1.pub_k.verify(z, minus_sig))
