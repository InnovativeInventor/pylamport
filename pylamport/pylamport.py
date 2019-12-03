import hashlib
import secrets


class Lamport:
    def __init__(self, hash_algo=hashlib.sha256):
        self.hash_algo = hash_algo
        self.private_key = [[],[]]
        self.public_key = [[],[]]

    def gen(self):
        """
        Generates a public/private key pair using the specified hashing
        algorithm.

        Returns: private_key, public_key
        """
        if self.is_key():
            raise AttributeError("Keys already generated")

        # hash_length = len(bin(int(self.hash_algo("".encode()).hexdigest(),
                              # 16)).split('b')[1])
        for i in range(2):
            for _ in range(int(self.hash_algo().digest_size) * 8):
                private_key = secrets.token_hex(32)
                try:
                    public_key = self.hash_algo(private_key.encode()).hexdigest()
                except AttributeError:
                    self.hash_algo = hashlib.sha256
                    public_key = self.hash_algo(private_key.encode()).hexdigest()

                self.private_key[i].append(private_key)
                self.public_key[i].append(public_key)

        self.private_key = tuple(self.private_key)
        self.public_key = tuple(self.public_key)
        return (self.private_key, self.public_key)
        # return self.export() # prevent infinite loops

    def export(self):
        if self.is_key():
            return (self.private_key, self.public_key)
        else:
            return self.gen()

    def is_key(self):
        """
        Check if there already exists a valid public and private keypair.
        """
        try:
            if self.private_key and self.public_key:
                if len(self.private_key[1]) + len(self.public_key[1]) > 0:
                    print(len(self.private_key[1])) # debug
                    return True
        except:
            return False

    def sign(self, msg: str):
        """
        Signs a public/private key pair using the public/private key pair.
        """
        self.msg = msg
        try:
            msg_hash = self.hash_algo(self.msg.encode()).hexdigest()
        except AttributeError:
            self.hash_algo = hashlib.sha256
            msg_hash = self.hash_algo(self.msg.encode()).hexdigest()

        msg_hash_bits = bin(int(msg_hash, 16)).split('b')[1]

        if not self.is_key():
            self.gen()

        hash_sign = []
        for count, each_bit in enumerate(msg_hash_bits):
            hash_sign.append(self.private_key[int(each_bit)][count])

        self.signature = Signature(self.msg, hash_sign, self.public_key, self.hash_algo)
        return self.signature

    def verify(self, signature):
        """
        Verifies the signature of the message.
        """
        self.msg = signature.msg
        self.hash_algo = signature.hash_algo
        self.public_key = signature.public_key

        msg_hash = self.hash_algo(self.msg.encode()).hexdigest()
        msg_hash_bits = bin(int(msg_hash, 16)).split('b')[1]

        # print(len(self.public_key[0]),len(self.public_key[1]))
        for count, each_bit in enumerate(msg_hash_bits):
            indiv_hash = self.hash_algo(signature.hash[count].encode()).hexdigest()
            # print(each_bit, count)
            if not indiv_hash == self.public_key[int(each_bit)][count]:
                raise ValueError('Invalid signature')

        return True


class Signature:
    def __init__(self, msg, hash_sign, public_key=None, hash_algo = hashlib.sha256):
        self.msg = msg
        self.hash = hash_sign
        self.hash_algo = hash_algo
        if public_key:
            self.public_key = public_key

    def __repr__(self):
        return str(self.msg) + " " + str(self.hash)
