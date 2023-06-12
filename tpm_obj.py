import sys
from dataclasses import dataclass
from typing import Optional
from amdnvtool import crypto
from Crypto.Cipher import AES

def kdf(key : bytes, bits : int, usage : str, context : bytes = b'') -> bytes:
  suffix = usage.encode() + b'\0' + context + bits.to_bytes(4, 'big')

  data = b''
  idx = 1
  while len(data) * 8 < bits:
    data += crypto.hmac_sha256(key, idx.to_bytes(4, 'big') + suffix)

  end = b''
  if bits % 8:
    end = bytes(list(data[bits//8] ^ ((1<<(bits%8))-1)))

  return data[:bits//8] + end

def aes128_cfb_dec(key : bytes, iv : bytes, data : bytes) -> bytes:
  assert len(key) == 0x10
  assert len(iv) == 0x10
  ext_len = (0x10 - len(data) % 16) % 16
  return AES.new(key, AES.MODE_CFB, iv, segment_size=128).decrypt(data + bytes(ext_len))[:-ext_len]
  
@dataclass
class TpmPersistanceKeys:
  seed : bytes
  hmac_key : bytes

  def aes_key(self, name : bytes) -> bytes:
    return kdf(self.seed, 0x10*8, 'STORAGE', name)

  def __post_init__(self):
    assert len(self.hmac_key) == 0x20
    assert len(self.aes_key(b'\x00\x0b' + bytes(0x20))) == 0x10

  @staticmethod
  def from_data(seed : bytes) -> 'TpmPersistanceKeys':
    assert len(seed) == 0x20
    return TpmPersistanceKeys(
      seed,
      kdf(seed, 0x20*8, 'INTEGRITY'),
    )
    
class TpmObjectReader:

  def __init__(self, data : bytes):
    self.__data = data
    self.__pos = 0
    self.__len = len(data)

  @staticmethod
  def get_wrapped(data : bytes):
    wrap_obj = TpmObjectReader(data)
    obj = wrap_obj.get_object()
    assert wrap_obj.is_empty()
    return obj

  def __get_bytes(self, count : int) -> bytes:
    assert count <= self.__len
    self.__len -= count
    data = self.__data[self.__pos:self.__pos+count]
    self.__pos += count
    return data

  def get_int(self, length : int, endianness : str = 'big') -> int:
    return int.from_bytes(self.__get_bytes(length), endianness)

  def get_data(self, length : int = None) -> bytes:
    return self.__get_bytes(self.get_int(2) if length is None else length)

  def get_rest_data(self) -> bytes:
    return self.__get_bytes(self.__len)

  def get_object(self) -> bytes:
    return TpmObjectReader(self.get_data())

  def is_empty(self) -> bool:
    return self.__len == 0

class TpmObjectWriter:

  def __init__(self):
    self.__data = bytes()

  def to_data(self):
    return self.__data

  def to_wrapped(self):
    wrap_obj = TpmObjectWriter()
    wrap_obj.add_data(self.__data)
    return wrap_obj

  def add_int(self, value : int, length : int, endianness : str = 'big'):
    self.__data += value.to_bytes(length, endianness)

  def add_data(self, data : bytes):
    self.add_int(len(data), 2)
    self.__data += data

  def add_data_raw(self, data : bytes):
    self.__data += data

@dataclass
class TpmBytes:
  length : int
  data : bytes

  @classmethod
  def from_reader(cls, obj : TpmObjectReader) -> 'TpmBytes':
    length = obj.get_int(2)
    data = obj.get_data(length)
    return cls(length, data)

  @classmethod
  def from_data(cls, data : bytes) -> 'TpmBytes':
    obj = TpmObjectReader(data)
    res = cls.from_reader(obj)
    assert obj.is_empty()
    return res

  def to_data(self) -> bytes:
    return self.length.to_bytes(2, 'big') + self.data

class TpmUnimplemented:

  def __init__(self, *a, **aa):
    raise NotImplementedError(self.__class__)

  @classmethod
  def from_data(cls, data : bytes):
    raise NotImplementedError(cls)

  @classmethod
  def from_reader(cls, obj : TpmObjectReader):
    raise NotImplementedError(cls)

class Tpm2bEccParameter(TpmBytes):
  pass

class Tpm2bSensitiveData(TpmBytes):
  pass

class Tpm2bSymKey(TpmBytes):
  pass

class Tpm2bPrivateVendorSpecific(TpmBytes):
  pass

@dataclass
class Tpm2bPrivateKeyRsa:
  bits : int
  prime_p : int

  @staticmethod
  def from_data(data : bytes) -> 'Tpm2bPrivateKeyRsa':
    obj = TpmObjectReader(data)
    length = obj.get_int(2)
    prime = obj.get_int(length)
    assert obj.is_empty()
    return Tpm2bPrivateKeyRsa(length * 8, prime)

TPM_ALG_RSA = 0x0001
TPM_ALG_KEYEDHASH = 0x0008
TPM_ALG_SHA256 = 0x000b
TPM_ALG_NULL = 0x0010
TPM_ALG_ECC = 0x0023
TPM_ALG_SYMCIPHER = 0x0025

class TpmUSensitiveComposite:

  VARIANTS = {
    TPM_ALG_RSA : Tpm2bPrivateKeyRsa,
    TPM_ALG_KEYEDHASH : Tpm2bSensitiveData,
    TPM_ALG_ECC : Tpm2bEccParameter,
    TPM_ALG_SYMCIPHER : Tpm2bSymKey,
  }
  DEFAULT = Tpm2bPrivateVendorSpecific

  __init__ = None

  @staticmethod
  def from_alg_and_data(algorithm : int, data : bytes):
    cls = TpmUSensitiveComposite.VARIANTS.get(
      algorithm, TpmUSensitiveComposite.DEFAULT,
    )
    return cls.from_data(data)


@dataclass
class Tpm2bSensitive:
  algorithm : int
  auth : bytes
  seed : bytes
  sensitive : TpmUSensitiveComposite

  @staticmethod
  def from_data(data : bytes) -> 'Tpm2bSensitive':
    obj = TpmObjectReader.get_wrapped(data)
    alg = obj.get_int(2)
    res = Tpm2bSensitive(
      alg,
      obj.get_data(),
      obj.get_data(),
      TpmUSensitiveComposite.from_alg_and_data(alg, obj.get_rest_data()),
    )
    assert obj.is_empty()
    return res

@dataclass
class Tpm2bPrivate:
  hmac : bytes
  iv : bytes
  sensitive : bytes

  def __post_init__(self):
    assert len(self.hmac) == 0x20
    assert len(self.iv) == 0x10

  @staticmethod
  def from_data(data : bytes) -> 'Tpm2bPrivate':
    obj = TpmObjectReader.get_wrapped(data)
    res = Tpm2bPrivate(
      obj.get_data(),
      obj.get_data(),
      obj.get_rest_data(),
    )
    assert obj.is_empty()
    return res

  def verify(self, hmac_key, name) -> bool:
    msg = len(self.iv).to_bytes(2, 'big') + self.iv + self.sensitive + name
    return self.hmac == crypto.hmac_sha256(hmac_key, msg)

  def unseal_sensitive_bytes(self, aes_key) -> bytes:
    return aes128_cfb_dec(aes_key, self.iv, self.sensitive)

  def unseal_sensitive(self, aes_key) -> Tpm2bSensitive:
    return Tpm2bSensitive.from_data(self.unseal_sensitive_bytes(aes_key))

@dataclass
class TpmSRsaParms:
  symmetric : int
  scheme : int
  key_bits : int
  exponent : int

  @staticmethod
  def from_reader(obj : TpmObjectReader) -> 'TpmSRsaParms':
    symmetric = obj.get_int(2)
    if symmetric != TPM_ALG_NULL:
      raise NotImplementedError(f"TpmSRsaParms currently only supports TPM_ALG_NULL not {symmetric:#02x} as symmetric field!")
    scheme = obj.get_int(2)
    if scheme != TPM_ALG_NULL:
      raise NotImplementedError(f"TpmSRsaParms currently only supports TPM_ALG_NULL not {scheme:#02x} as scheme field!")
    key_bits = obj.get_int(2)
    exponent = obj.get_int(4)
    return TpmSRsaParms(
      symmetric, scheme, key_bits, exponent
    )

  def to_data(self) -> bytes:
    obj = TpmObjectWriter()
    obj.add_int(self.symmetric, 2)
    obj.add_int(self.scheme, 2)
    obj.add_int(self.key_bits, 2)
    obj.add_int(self.exponent, 4)
    return obj.to_data()

class TpmSKeyedHashParms(TpmUnimplemented):
  pass

class TpmSEccParms(TpmUnimplemented):
  pass

class TpmSSymCipherParms(TpmUnimplemented):
  pass

class TpmSAsymParms(TpmUnimplemented):
  pass

class TpmUPublicParms:

  VARIANTS = {
    TPM_ALG_RSA : TpmSRsaParms,
    TPM_ALG_KEYEDHASH : TpmSKeyedHashParms,
    TPM_ALG_ECC : TpmSEccParms,
    TPM_ALG_SYMCIPHER : TpmSSymCipherParms,
  }
  DEFAULT = TpmSAsymParms

  __init__ = None

  @staticmethod
  def from_alg_and_reader(algorithm : int, obj : TpmObjectReader):
    cls = TpmUPublicParms.VARIANTS.get(
      algorithm, TpmUPublicParms.DEFAULT,
    )
    return cls.from_reader(obj)

class Tpm2bDigest(TpmBytes):
  pass

@dataclass
class Tpm2bPublicKeyRsa:
  length : int
  modulus : int

  @staticmethod
  def from_reader(obj : TpmObjectReader) -> 'Tpm2bPublicKeyRsa':
    length = obj.get_int(2)
    modulus = obj.get_int(length)
    return Tpm2bPublicKeyRsa(length, modulus)

  @staticmethod
  def from_data(data : bytes) -> 'Tpm2bPublicKeyRsa':
    obj = TpmObjectReader(data)
    res = Tpm2bPublicKeyRsa.from_reader(obj)
    assert obj.is_empty()
    return res

  def to_data(self) -> bytes:
    obj = TpmObjectWriter()
    obj.add_int(self.length, 2)
    obj.add_int(self.modulus, self.length)
    return obj.to_data()

class TpmSEccPoint(TpmUnimplemented):
  pass

class TpmSDerive(TpmUnimplemented):
  pass

class TpmUPublicId:

  VARIANTS = {
    TPM_ALG_RSA : Tpm2bPublicKeyRsa,
    TPM_ALG_KEYEDHASH : Tpm2bDigest,
    TPM_ALG_ECC : TpmSEccPoint,
    TPM_ALG_SYMCIPHER : Tpm2bDigest,
  }
  DEFAULT = TpmSDerive

  __init__ = None

  @staticmethod
  def from_alg_and_reader(algorithm : int, obj : TpmObjectReader):
    cls = TpmUPublicId.VARIANTS.get(
      algorithm, TpmUPublicId.DEFAULT,
    )
    return cls.from_reader(obj)

@dataclass
class Tpm2bPublic:
  algorithm : int
  name_alg  : int
  attributes : int
  auth_policy : bytes
  params : TpmUPublicParms
  unique : TpmUPublicId

  @staticmethod
  def from_data(data : bytes) -> 'Tpm2bPublic':
    obj = TpmObjectReader.get_wrapped(data)
    alg = obj.get_int(2)
    res = Tpm2bPublic(
      alg,
      obj.get_int(2),
      obj.get_int(4),
      obj.get_data(),
      TpmUPublicParms.from_alg_and_reader(alg, obj),
      TpmUPublicId.from_alg_and_reader(alg, obj),
    )
    assert obj.is_empty()
    return res

  def public_area_data(self) -> bytes:
    obj = TpmObjectWriter()
    obj.add_int(self.algorithm, 2)
    obj.add_int(self.name_alg, 2)
    obj.add_int(self.attributes, 4)
    obj.add_data(self.auth_policy)
    obj.add_data_raw(self.params.to_data())
    obj.add_data_raw(self.unique.to_data())
    return obj.to_data()

  def to_data(self) -> bytes:
    obj = TpmObjectWriter()
    obj.add_data(self.public_area_data())
    return obj.to_data()

  def name(self) -> bytes:
    return b'\x00\x0b' + crypto.sha256(self.public_area_data())

def load_data(filename : str):
  with open(filename, "rb") as f:
    return f.read()

def get_sensitive(keys : TpmPersistanceKeys, pub : Tpm2bPublic, priv : Tpm2bPrivate) -> bytes:
  name = pub.name()
  assert priv.verify(keys.hmac_key, name)
  return priv.unseal_sensitive(keys.aes_key(name))

if __name__ == "__main__":
  
  def print_usage():
    print(f"{sys.argv[0]} <primary seed (hex)> <tpm object pub file> <tpm object priv file>")

  if len(sys.argv) < 2:
    print("Error no primary seed given!")
    print_usage()
    exit(-1)
  primary_seed = bytes.fromhex(sys.argv[1])

  if len(sys.argv) < 3:
    print("Error no tpm object public file given!")
    print_usage()
    exit(-1)
  tpm_pub_bytes = load_data(sys.argv[2])

  if len(sys.argv) < 4:
    print("Error no tpm object private file given!")
    print_usage()
    exit(-1)
  tpm_priv_bytes = load_data(sys.argv[3])

  keys = TpmPersistanceKeys.from_data(primary_seed[::-1])
  public = Tpm2bPublic.from_data(tpm_pub_bytes)
  private = Tpm2bPrivate.from_data(tpm_priv_bytes)
  sensitive = get_sensitive(keys, public, private)

  print("TPM_KEYS {")
  print(f"  hmac_key = {keys.hmac_key.hex()}")
  print(f"  aes_key(name) = {keys.aes_key(public.name()).hex()}")
  print("}")
  print()
  print("TPM_2B_PUBLIC {")
  print(f"  algorithm = {public.algorithm:#06x}")
  print(f"  name_alg = {public.name_alg:#06x}")
  print(f"  attributes = {public.attributes:#010x}")
  print(f"  auth_policy = {public.auth_policy.hex()}")
  print(f"  params = {public.params}")
  print(f"  unique = {public.unique}")
  print("}")
  print()
  print("TPM_2B_PRIVATE {")
  print(f"  hmac = {private.hmac.hex()}")
  print(f"  iv = {private.iv.hex()}")
  print(f"  sensitive = {private.sensitive.hex()}")
  print("}")
  print()
  print("TPM_2B_SENSITIVE {")
  print(f"  algorithm = {sensitive.algorithm:#06x}")
  print(f"  auth = {sensitive.auth.hex()}")
  print(f"  seed = {sensitive.seed.hex()}")
  print(f"  sensitive = {sensitive.sensitive}")
  print("}")

