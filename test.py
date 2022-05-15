from hmac import HMAC
from hashlib import md5

h = HMAC(b"key", b"The quick brown fox jumps over the lazy dog", md5)
print(h.hexdigest())
