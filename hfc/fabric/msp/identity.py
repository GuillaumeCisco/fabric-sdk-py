import logging

from hfc.protos.msp import identities_pb2

_logger = logging.getLogger(__name__)
_logger.setLevel(logging.DEBUG)


class Identity(object):

    def __init__(self, certificate, publicKey, mspId, cryptoSuite):

        if not certificate:
            raise Exception('Missing required parameter "certificate".')

        if not mspId:
            raise Exception('Missing required parameter "mspId".')

        self._certificate = certificate
        self._publicKey = publicKey
        self._mspId = mspId
        self._cryptoSuite = cryptoSuite

    @property
    def mspid(self):
        return self._mspId

    def isValid(self):
        return True

    def getOrganizationUnits(self):
        raise Exception('not yet implemented')

    def verify(self, msg, signature, opts):
        # TODO: retrieve the publicKey from the certificate
        if not self._publicKey:
            raise Exception('Missing public key for this Identity')
        if not self._cryptoSuite:
            raise Exception('Missing cryptoSuite for this Identity')

        return self._cryptoSuite.verify(self._publicKey, signature, msg)

    # TODO: when this method's design is finalized
    def verifyAttributes(self, proof, attributeProofSpec):
        return True

    def serialize(self):
        # looks a bit like create_serialized_identity
        serialized_identity = identities_pb2.SerializedIdentity()
        serialized_identity.mspid = self.mspid
        serialized_identity.id_bytes = self._certificate
        return serialized_identity.SerializeToString()


class Signer(object):

    def __init__(self, cryptoSuite, key):
        if not cryptoSuite:
            raise Exception('Missing required parameter "cryptoSuite"')

        if not key:
            raise Exception('Missing required parameter "key" for private key')

        self._cryptoSuite = cryptoSuite
        self._key = key

    def getPublicKey(self):
        return self._key.getPublicKey()

    def sign(self, digest):
        return self._cryptoSuite.sign(self._key, digest)


class SigningIdentity(Identity):

    def __init__(self, certificate, publicKey, mspId, cryptoSuite, signer):

        if not publicKey:
            raise Exception('Missing required parameter "publicKey".')

        if not publicKey:
            raise Exception('Missing required parameter "publicKey".')

        if not cryptoSuite:
            raise Exception('Missing required parameter "cryptoSuite".')

        super(SigningIdentity, self).__init__(certificate, publicKey, mspId, cryptoSuite)

        if not signer:
            raise Exception('Missing required parameter "signer".')

        self._signer = signer

    # TODO review
    def sign(self, msg, opts):
        if opts and 'hashFunction' in opts and opts['hashFunction']:
            if not hasattr(opts['hashFunction'], '__call__'): # is function?
                raise Exception('The "hashFunction" field must be a function')
            hashFunction = opts['hashFunction']
        else:
            hashFunction = self._cryptoSuite.hash

        digest = hashFunction(msg)
        return self._signer.sign(digest.hexdigest())

