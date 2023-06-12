import sys
import math
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def hex_to_int_be(hex_str : str) -> int:
  return int.from_bytes(bytes.fromhex(hex_str), 'big')

def rsa_privkey_from_n_and_p(n : int, p : int, e : int = 0x10001):

  pub_nrs = rsa.RSAPublicNumbers(e, n)

  q = n // p
  assert n == p*q

  # lambda(n) = lcm(p-1,q-1) = (p-1)(q-1) / gcd(p-1,q-1)
  lam_n = (p-1)*(q-1) // math.gcd(p-1,q-1)

  assert math.gcd(e, lam_n) == 1

  d = pow(e, -1, lam_n)

  priv_nrs = rsa.RSAPrivateNumbers(
    p, q, d,
    rsa.rsa_crt_dmp1(d, p),
    rsa.rsa_crt_dmq1(d, q),
    rsa.rsa_crt_iqmp(p, q),
    pub_nrs,
  )

  return priv_nrs.private_key()

def privkey_to_pem_key(priv_key) -> str:
  return priv_key.private_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PrivateFormat.PKCS8,
    encryption_algorithm = serialization.NoEncryption(),
  ).decode()

if __name__ == "__main__":
  
  def print_usage():
    print(f"{sys.argv[0]} <modulus n> <prime p> [output file]")

  if len(sys.argv) < 2:
    print("Error: no modulus given!")
    print_usage()
    exit(-1)
  n = int(sys.argv[1])

  if len(sys.argv) < 3:
    print("Error: no prime p given!")
    print_usage()
    exit(-1)
  p = int(sys.argv[2])

  output_file = None
  if len(sys.argv) >= 4:
    output_file = sys.argv[3]

  priv_key = rsa_privkey_from_n_and_p(n, p)
  pem_text = privkey_to_pem_key(priv_key)

  if output_file is None:
    print(pem_text)
  else:
    with open(output_file, "w") as f:
      f.write(pem_text)
  
