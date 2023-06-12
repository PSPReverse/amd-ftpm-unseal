import sys, json

import Crypto.IO.PEM as pem
import asn1tools

import tpm_obj
from recover_rsa_key import rsa_privkey_from_n_and_p, privkey_to_pem_key
from gen_prim_seed import primary_object_seed
from amdnvtool.nv_data import NVData

TPM_KEY_DECODER = asn1tools.compile_string("""
TPMKey DEFINITIONS ::= BEGIN
  TPMKey ::= SEQUENCE {
    type        OBJECT IDENTIFIER,
    authEmpty   [0] BOOLEAN OPTIONAL,
    parent      INTEGER,
    publicKey   OCTET STRING,
    privateKey  OCTET STRING
  }
END
""")

def load_tpm_key_file(filename : str):
  with open(filename) as f:
    data, usage, _ = pem.decode(f.read())
  assert usage == "TSS2 PRIVATE KEY"
  return TPM_KEY_DECODER.decode("TPMKey", data)

def load_json_file(filename : str):
  with open(filename) as f:
    return json.load(f)

def print_or_write_str(key_str, output_file):
  if output_file is not None:
    with open(output_file, "w") as f:
      f.write(key_str)
  else:
    print(key_str)

TESLA_TEMPLATE = bytes.fromhex('0023000b00030472000000060080004300100003001000000000')

def nvdata_and_tpm_bytes_to_privkey(nvdata, tpm_pub_bytes, tpm_priv_bytes):
  primary_seed = primary_object_seed(nvdata, TESLA_TEMPLATE, 0x20)
  tpm_keys = tpm_obj.TpmPersistanceKeys.from_data(primary_seed[::-1])
  tpm_public = tpm_obj.Tpm2bPublic.from_data(tpm_pub_bytes)
  tpm_private = tpm_obj.Tpm2bPrivate.from_data(tpm_priv_bytes)
  tpm_sensitive = tpm_obj.get_sensitive(tpm_keys, tpm_public, tpm_private)
  return rsa_privkey_from_n_and_p(
    tpm_public.unique.modulus, tpm_sensitive.sensitive.prime_p
  )

if __name__ == "__main__":

  def print_usage():
    print("Usage:")
    print(f"  {sys.argv[0]} <command> [<args ...>]")
    print("Commands:")
    print("""
  from-nvdata <nvdata.json> <car-creds.key> [<car-creds-unsealed.key>]
  from-image <flash-image.bin> <secret (hex)> <car-creds.key> [<car-creds-unsealed.key>]
""")

  if len(sys.argv) < 2:
    print("Error: no command given!")
    print_usage()
    exit(-1)
  command = sys.argv[1]

  if command == "from-nvdata":

    if len(sys.argv) < 3:
      print("Error: <nvdata.json> not given!")
      print_usage()
      exit(-1)
    nvdata = load_json_file(sys.argv[2])

    if len(sys.argv) < 4:
      print("Error: <car-creds.key> not given!")
      print_usage()
      exit(-1)
    car_creds = load_tpm_key_file(sys.argv[3])

    output_file = sys.argv[4] if len(sys.argv) > 4 else None

    privkey = nvdata_and_tpm_bytes_to_privkey(
      nvdata, car_creds["publicKey"], car_creds["privateKey"]
    )
    key_str = privkey_to_pem_key(privkey)

    print_or_write_str(key_str, output_file)

  elif command == "from-image":

    if len(sys.argv) < 3:
      print("Error: <flash-image.bin> not given!")
      print_usage()
      exit(-1)
    flash_image = sys.argv[2]

    if len(sys.argv) < 4:
      print("Error: <secret (hex)> not given!")
      print_usage()
      exit(-1)
    secret_hex = sys.argv[3]

    if len(sys.argv) < 5:
      print("Error: <car-creds.key> not given!")
      print_usage()
      exit(-1)
    car_creds = load_tpm_key_file(sys.argv[4])

    output_file = sys.argv[5] if len(sys.argv) > 5 else None

    nvdata = NVData.from_file_and_secret_hex(flash_image, secret_hex)

    nvdata = [{
      'context' : context_id,
      'sequence' : [[bs.hex() for bs in content] if content else None for content in sequence],
    } for (context_id, sequence) in nvdata.by_context.items()]

    privkey = nvdata_and_tpm_bytes_to_privkey(
      nvdata, car_creds["publicKey"], car_creds["privateKey"]
    )
    key_str = privkey_to_pem_key(privkey)

    print_or_write_str(key_str, output_file)

  else:
    print(f"Error: unknown command \"{command}\" given!")
    print_usage()
    exit(-1)
