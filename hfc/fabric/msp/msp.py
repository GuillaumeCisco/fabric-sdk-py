import logging

from hfc.fabric.block_decoder import decode_identity
from hfc.fabric.msp.identity import SigningIdentity, Identity

_logger = logging.getLogger(__name__)
_logger.setLevel(logging.DEBUG)


class MSP(object):

    def __init__(self, config):
        _logger.debug('const - start')
        if not config:
            raise Exception('Missing required parameter "config"')
        if not config['id']:
            raise Exception('Parameter "config" missing required field "id"')
        if not config['cryptoSuite']:
            raise Exception('Parameter "config" missing required field "cryptoSuite"')

        if 'signer' not in config or config['signer'] is None:
            if not isinstance(config['signer'], SigningIdentity):
                raise Exception('Parameter "signer" must be an instance of SigningIdentity')

        self._rootCerts = config['rootCerts']
        self._intermediateCerts = config['intermediateCerts']
        self._signer = config['signer']
        self._admins = config['admins']
        self.cryptoSuite = config['cryptoSuite']
        self._id = config['id']
        self._organization_units = config['orgs']
        self._tls_root_certs= config['tls_root_certs']
        self._tls_intermediate_certs = config['tls_intermediate_certs']

    @property
    def id(self):
        return self._id

    @property
    def organization_units(self):
        return self._organization_units

    @property
    def policy(self):
        raise Exception('Not implemented yet')

    @property
    def policy(self):
        raise Exception('Not implemented yet')

    def getSigningIdentity(self, identifier):
        raise Exception('Not implemented yet')

    def getDefaultSigningIdentity(self):
        return self._signer

    def deserializeIdentity(self, serializedIdentity, storeKey):
        _logger.debug('importKey - start')
        store_key = True # default

        if isinstance(storeKey, bool):
            store_key = storeKey

        sid = decode_identity(serializedIdentity)
        cert = sid['id_bytes'] # TODO review

        _logger.debug(f'Encoded cert from deserialized identity: {cert}')

        if not store_key:
            publicKey = self.cryptoSuite # TODO find a way to get public key from cert
            sdk_identity = Identity(cert, publicKey, self.id, self.cryptoSuite)
            return sdk_identity
        else:
            # TODO find a way to get public key from cert
            return self.cryptoSuite

    def validate(self, id):
        return True
