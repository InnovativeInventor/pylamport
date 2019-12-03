import hashlib
import secrets

import pytest

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

def test_error_key_already_generated():
    identity = pylamport.Lamport()
    identity.gen()

    with pytest.raises(AttributeError) as error:
        identity.gen()
    assert 'Keys already generated' == str(error.value)

def test_just_sign():
    identity = pylamport.Lamport()
    signature = pylamport.Lamport().sign("test")
    assert identity.verify(signature)
    assert len(repr(signature)) > 10

def test_is_key():
    test = pylamport.Lamport().is_key()
    assert test == False

def error_test_forged_signature():
    identity = pylamport.Lamport()
    signature = pylamport.Lamport().sign("test")
    alt_signature = pylamport.Lamport().sign("test")
    forged_signature = pylamport.Signature(signature.msg, signature.hash,
                                           alt_signature.public_key)
    with pytest.raises(ValueError) as error:
        identity.verify(forged_signature)
    assert "Invalid signature" == error
