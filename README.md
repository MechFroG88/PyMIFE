# PyMIFE

Multi input functional encryption library for python

## Installation

```bash
pip install pymife
```

## Schemes

### Single input inner product
1. (Selective Secure) DDH based scheme from https://eprint.iacr.org/2015/017.pdf
2. (Selective Secure) LWE based scheme from https://eprint.iacr.org/2015/017.pdf
3. (Adaptive Secure) Damgard based scheme from https://eprint.iacr.org/2015/608.pdf

### Multi input inner product
1. (Adaptive Secure) Damgard based scheme from https://eprint.iacr.org/2017/972.pdf

### Multi client inner product 
1. (Adaptive Secure with Random Oracle) DDH based scheme from https://eprint.iacr.org/2017/989.pdf

## Note
- The implementation of these schemes are not fully optimized, recommended to use for research / testing purpose.
- More schemes will be added in the future

## Usage

### Single input inner product

#### DDH based scheme

```python
from mife.single.ddh import FeDDH

n = 10
x = [i for i in range(n)]
y = [i + 10 for i in range(n)]
key = FeDDH.generate(n)
c = FeDDH.encrypt(x, key)
sk = FeDDH.keygen(y, key)
m = FeDDH.decrypt(c, key, sk, (0, 1000))
```

#### LWE based scheme

```python
from mife.single.lwe import FeLWE

n = 10
x = [i - 10 for i in range(n)]
y = [i for i in range(n)]
key = FeLWE.generate(n, 4, 4)
c = FeLWE.encrypt(x, key)
sk = FeLWE.keygen(y, key)
m = FeLWE.decrypt(c, key, sk) % key.p
```

#### Damgard based scheme

```python
from mife.single.damgard import FeDamgard

n = 10
x = [i for i in range(n)]
y = [i + 10 for i in range(n)]
key = FeDamgard.generate(n)
c = FeDamgard.encrypt(x, key)
sk = FeDamgard.keygen(y, key)
m = FeDamgard.decrypt(c, key, sk, (0, 1000))
```

### Multi input inner product

#### Damgard based scheme

```python
from mife.multi.damgard import FeDamgardMulti

n = 3
m = 5
x = [[i + j for j in range(m)] for i in range(n)]
y = [[i - j + 10 for j in range(m)] for i in range(n)]
key = FeDamgardMulti.generate(n, m)
cs = [FeDamgardMulti.encrypt(x[i], key.get_enc_key(i)) for i in range(n)]
sk = FeDamgardMulti.keygen(y, key)
m = FeDamgardMulti.decrypt(cs, key, sk, (0, 2000))
```

Using Curve25519

```python
from mife.multi.damgard import FeDamgardMulti
from mife.data.curve25519 import Curve25519

n = 25
m = 25
x = [[i * 10 + j for j in range(m)] for i in range(n)]
y = [[i - j - 5 for j in range(m)] for i in range(n)]
key = FeDamgardMulti.generate(n, m, Curve25519)
cs = [FeDamgardMulti.encrypt(x[i], key.get_enc_key(i)) for i in range(n)]
sk = FeDamgardMulti.keygen(y, key)
res = FeDamgardMulti.decrypt(cs, key, sk, (-10000000, 10000000))
```

### Multi client inner product

#### DDH based scheme

```python
from mife.multiclient.ddh import FeDDHMultiClient

n = 3
m = 5
x = [[i + j for j in range(m)] for i in range(n)]
y = [[i - j + 10 for j in range(m)] for i in range(n)]
tag = b"testingtag123"
key = FeDDHMultiClient.generate(n, m)
cs = [FeDDHMultiClient.encrypt(x[i], tag, key.get_enc_key(i)) for i in range(n)]
sk = FeDDHMultiClient.keygen(y, key)
m = FeDDHMultiClient.decrypt(cs, tag, key, sk, (0, 2000))
```

## Customize

All of the DDH and Damgard schemes support custom group. You can implement your own group class by extending `/src/mife/data/group.py` as base class.

To use custom group, simply pass the group class to the `generate` function.

This library has implemented prime order group and curve25519 group.

For MCFE-DDH scheme, you can also supply your own hash function by using the same signature as the default hash function found in `/src/mife/multiclient/ddh.py`.

## References

- https://eprint.iacr.org/2015/017.pdf
- https://eprint.iacr.org/2015/608.pdf
- https://eprint.iacr.org/2017/972.pdf
- https://eprint.iacr.org/2017/989.pdf
- https://github.com/fentec-project/CiFEr/blob/master/src/innerprod/simple/lwe.c