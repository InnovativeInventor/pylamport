## Pylamport
A python library for producing lamport signatures.

Lamport signatures can be constructed with any secure one-way function (usually
a hash).

Anything in hashlib (for example, `hashlib.sha256`) is supported.

## Example usage
Generating keys:
```python
keys = pylamport.Lamport().gen()
```

Signing a message:
```python
identity = pylamport.Lamport()
signature = identity.sign("Hello, world!")
```

Verifiying a signature:
```python
identity = pylamport.Lamport()
identity.verify(signature)
```

Exporting keys:
```python
identity = pylamport.Lamport()
keys = identity.export()
```

## Warnings
This project was written in less than a few hours, so it may contain mistakes
and/or bugs.
