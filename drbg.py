from cryptography.hazmat.primitives import hashes, hmac, ciphers
from cryptography.hazmat.primitives.ciphers import algorithms

def xor(ls,rs):
  return bytes(l^r for (l,r) in zip(ls, rs))

class DrbgSeedGen:
  """generates the seed for the drbg"""

  __KEY = bytes(range(0, 0x20))

  __AES_CTX = ciphers.Cipher(algorithms.AES(__KEY), ciphers.modes.ECB()).encryptor()

  @staticmethod
  def __aes_enc_1(bs):
    assert len(bs) == 0x10
    return DrbgSeedGen.__AES_CTX.update(bs)

  @staticmethod
  def __aes_enc(b):
    return (
      DrbgSeedGen.__aes_enc_1(b[0]),
      DrbgSeedGen.__aes_enc_1(b[1]),
      DrbgSeedGen.__aes_enc_1(b[2]),
    )

  @staticmethod
  def __shuffle(b, mixin):
    t = xor(b[0], mixin)
    b1 = xor(b[0], b[1])
    b2 = xor(t, xor(b[1], b[2]))
    return (t, b1, b2)


  @staticmethod
  def __first_block(input_len, output_len):
    assert output_len == 0x30

    block = DrbgSeedGen.__aes_enc((
      bytes(16),
      int(1).to_bytes(4, "big") + bytes(12),
      int(3).to_bytes(4, "big") + bytes(12),
    ))

    block = (bytes(8) + block[0][8:], block[1], block[2])

    lengths = input_len.to_bytes(4, 'big') + output_len.to_bytes(4,'big') + bytes(8)

    return (xor(lengths, block[0]), block[1], block[2])

  @staticmethod
  def __next_block(block, bs):
    return DrbgSeedGen.__aes_enc(DrbgSeedGen.__shuffle(block, bs))

  @staticmethod
  def gen_seed_0x30(input_bytes):
    mixin_bytes = bytes(4) + input_bytes + b'\x80'

    to_pad = 0x10 - (len(mixin_bytes) % 0x10)
    if to_pad != 0x10:
      mixin_bytes += bytes(to_pad)

    block = DrbgSeedGen.__first_block(len(input_bytes), 0x30)
    for i in range(0,len(mixin_bytes),0x10):
      block = DrbgSeedGen.__next_block(block, mixin_bytes[i:i+0x10])

    return block[0] + block[1] + block[2]

  @staticmethod
  def __deshuffle(b, res):
    b0 = b[0]
    b1 = xor(b0, b[1])
    b2 = xor(b1, b[2])
    r0 = xor(b0, res[0])
    assert xor(b1, res[1]) == bytes(16)
    assert r0 == xor(b2, res[2])
    return r0

  @staticmethod
  def __bytes_to_block(bs):
    assert len(bs) == 0x30
    return (bs[:0x10], bs[0x10:0x20], bs[0x20:])

  @staticmethod
  def dec_seed_0x30(aes_input_bytes):
    assert len(aes_input_bytes) % 0x30 == 0
    assert len(aes_input_bytes) >= 0x60
    assert aes_input_bytes[0x00:0x10] == bytes(16)
    assert aes_input_bytes[0x10:0x20] == b'\x00\x00\x00\x01' + bytes(12)
    assert aes_input_bytes[0x20:0x30] == b'\x00\x00\x00\x03' + bytes(12)

    inpl = int.from_bytes(aes_input_bytes[0x30:0x34], 'big')
    block = DrbgSeedGen.__first_block(inpl, 0x30)
    res = DrbgSeedGen.__deshuffle(block, DrbgSeedGen.__bytes_to_block(aes_input_bytes[0x30:0x60]))
    for i in range(0x60,len(aes_input_bytes),0x30):
      res += DrbgSeedGen.__deshuffle(
        DrbgSeedGen.__aes_enc(DrbgSeedGen.__bytes_to_block(aes_input_bytes[i-0x30:i])),
        DrbgSeedGen.__bytes_to_block(aes_input_bytes[i:i+0x30]),
      )

    assert res[:4] == bytes(4)
    assert res[4+inpl:] == b'\x80' + bytes(len(res)-4-inpl-1)

    return res[4:4+inpl]

# test

if __name__ == "__main__":

  ctx_256_last_6_bytes = bytes.fromhex('be0463905368')
  ctx_257_first_26_bytes = bytes.fromhex('e44e445ec37335e3caadbeb2951791736f154efdeefe587fcfc8')

  use_string = b'Primary Object Creation\0'

  template_digest = b'\0\x0b' + bytes.fromhex("c1f5407dc841693abb059678b8218973735dc27499c480732d5f64d1dad8f010")[::-1]

  seed_gen_inp = ctx_256_last_6_bytes + ctx_257_first_26_bytes + use_string + template_digest

  print(f"input:  {seed_gen_inp.hex()}")

  result = bytes.fromhex('5705ee94d2849a0f1830a4bbba8296b972588998e00d452be45857d77e0078b8bdc8b6a5c74496e9eb2362f7c404c193')

  print(f"result: {result.hex()}")

  res = DrbgSeedGen.gen_seed_0x30(seed_gen_inp)

  print(f"res:    {res.hex()}")

  assert res == result

  inputs = [
    "00000000000000000000000000000000",
    "00000001000000000000000000000000",
    "00000003000000000000000000000000",
    "0000005abe0463a0fa9b7e249970b4f3",
    "9dba41fd77f3b45a9e4430c494f8a80d",
    "bf1f585387b3e75f4f294219b9d3da63",
    "eaeedc21eb5b16f12c1ee6f4541cdd12",
    "ca7e66d6094b7e7249093e3b37b6447c",
    "fafa13ec5f836115896112bc3be73c60",
    "fcda95c57b9fb387cf71952a71dc484b",
    "9d42ba1a97998451bff2406d460d1f6b",
    "1ec7ad6a798d9b6e4fdee9a588c6c49d",
    "a710b53e0f7698dc529fb45bba8150ce",
    "7190364a71a83ca86a40bfaf8eb54814",
    "d83eba43419be43810054749289a5b0d",
    "201d7f39852d9553f8387603c3cd717c",
    "166298ad24616567a45e2370cf1d0758",
    "6b1ff0028f962d169f915a9061aa03ae",
    "f57e1c3e96e0bae7c6fb23a30250474e",
    "db87c9779876028ff86501421a179862",
    "0f61d00cbace938115aa054e5aae6f4c"
  ]
  inputs = b''.join(bytes.fromhex(s) for s in inputs)

  inp = DrbgSeedGen.dec_seed_0x30(inputs)

  print(f"inp:    {inp.hex()}")

  assert inp == seed_gen_inp

class Drbg:

  def __init__(self, seed):
    assert seed is not None
    self.__key = bytes(0x20)
    self.__value = bytes(0x10)
    self.generate(0, seed)

  def __inc_val(self):
    self.__value = (int.from_bytes(self.__value, 'big') + 1).to_bytes(0x10, 'big')

  def __gen_block(self, enc):
    self.__inc_val()
    return enc.update(self.__value)

  def generate(self, to_generate, data = None):
    enc = ciphers.Cipher(algorithms.AES(self.__key), ciphers.modes.ECB()).encryptor()
    res = bytes()
    while len(res) < to_generate:
      res += self.__gen_block(enc)

    new_state = self.__gen_block(enc)
    new_state += self.__gen_block(enc)
    new_state += self.__gen_block(enc)
    if data is not None:
      assert len(data) == 0x30
      new_state = xor(new_state, data)

    self.__key = new_state[:0x20]
    self.__value = new_state[0x20:]

    return res[:to_generate]

# test

if __name__ == "__main__":

  seed = bytes.fromhex('5705ee94d2849a0f1830a4bbba8296b972588998e00d452be45857d77e0078b8bdc8b6a5c74496e9eb2362f7c404c193')

  key = bytes.fromhex('a0e5f3c4049216e3452e6dada5c9ffbc32e5497e4a1053b1b6acc1156f640a04')[::-1]
  value = bytes.fromhex('cfa8b56ff0e2bc9d3a819779b102f41d')

  drbg = Drbg(seed)

  print(f'key:   {key.hex()}')
  print(f'key:   {drbg._Drbg__key.hex()}')
  assert drbg._Drbg__key == key
  print(f'value: {value.hex()}')
  print(f'value: {drbg._Drbg__value.hex()}')
  assert drbg._Drbg__value == value

  gen0 = bytes.fromhex('a99323107963267e296ccfff7dbcdf1b03c183fc1b723f550d7c9844fa97e17c')
  print(f'gen0:  {gen0.hex()}')
  g0 = drbg.generate(0x20)
  print(f'g0:    {g0.hex()}')
  assert g0 == gen0

  gen1 = bytes.fromhex('32d47d256f3e8640371c21fa3509e1537d55de183ef93d4a2ed6b35eac51c192')
  print(f'gen1:  {gen1.hex()}')
  g1 = drbg.generate(0x20)
  print(f'g1:    {g1.hex()}')
  assert g1 == gen1

  

