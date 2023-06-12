import sys, json

from cryptography.hazmat.primitives import hashes

from drbg import *

def sha256(message):
  ctx = hashes.Hash(hashes.SHA256())
  ctx.update(message)
  return ctx.finalize()

def get_nvdata_context(nvdata, nr):
  res = None
  for c in nvdata:
    if c['context'] == nr:
      res =  c['sequence']
      break
  if res is None:
    raise KeyError(nr)
  return res

def primary_object_drbg_seed_context(nvdata, template):
  ctx256 = bytes.fromhex(get_nvdata_context(nvdata, 256)[-1][0])
  ctx257 = bytes.fromhex(get_nvdata_context(nvdata, 257)[-1][0])
  name = b'\x00\x0b' + sha256(template)
  return ctx256[-6:] + ctx257[:0x20-6] + b'Primary Object Creation\0' + name

def primary_object_drbg(nvdata, template):
  seed_input = primary_object_drbg_seed_context(nvdata, template)
  seed = DrbgSeedGen.gen_seed_0x30(seed_input)
  return Drbg(seed)

def primary_object_seed(nvdata, template, pre_seed_bytes):
  drbg = primary_object_drbg(nvdata, template)
  drbg.generate(pre_seed_bytes)
  return drbg.generate(0x20)

if __name__ == "__main__":

  def print_usage():
    print(f"{sys.argv[0]} <nvdata.json> <template (hex)> <pre seed bytes>")
    print("""
  nvdata.json
    created with amdnvtool
  template (hex)
    hex encoded representation of the primary object template
  pre seed bytes
    bytes taken from the drbg before the seed is generated
""")

  if len(sys.argv) < 2:
    print("Error: no nvdata.json given!")
    print_usage()
    exit(-1)

  with open(sys.argv[1]) as f:
    nvdata = json.load(f)

  if len(sys.argv) < 3:
    print("Error: no template (hex) given!")
    print_usage()
    exit(-1)

  template = bytes.fromhex(sys.argv[2])

  if len(sys.argv) < 4:
    print("Error: no pre seed bytes given!")
    print_usage()
    exit(-1)

  try:
    pre_seed_bytes = int(sys.argv[3])
  except ValueError:
    pre_seed_bytes = int(sys.argv[3], 16)

  print(primary_object_seed(nvdata, template, pre_seed_bytes).hex())

