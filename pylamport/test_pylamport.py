import hashlib
import secrets

from pylamport import pylamport


def test_lamport():
    msg = secrets.token_hex(16)
    identity = pylamport.Lamport()
    identity.gen()
    signature = identity.sign(msg)
    assert identity.verify(signature)

def test_gen():
    gen = pylamport.Lamport(hash_algo = hashlib.sha512).gen()
    assert isinstance(gen, tuple)

def test_sign():
    msg = secrets.token_hex(16)
    identity = pylamport.Lamport(hash_algo = hashlib.blake2b)
    signature = identity.sign(msg)
    assert isinstance(signature, pylamport.Signature)
    assert identity.verify(signature)

    verify_instance = pylamport.Lamport(hash_algo = hashlib.blake2b)
    assert verify_instance.verify(signature)

    assert pylamport.Lamport(hash_algo = hashlib.blake2b).verify(signature)

def test_no_key():
    msg = secrets.token_hex(16)
    identity = pylamport.Lamport()
    signature = identity.sign(msg)
    assert identity.verify(signature)
    assert identity.export()
    assert isinstance(identity.export(), tuple)

def test_plain_export():
    assert isinstance(pylamport.Lamport().export(), tuple)

def test_ordinary_export():
    identity = pylamport.Lamport(hash_algo = hashlib.blake2b)
    assert identity.gen() == identity.export()
