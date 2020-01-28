import logging

from hfc.fabric.block_decoder import decode_fabric_MSP_config, decode_identity
from hfc.fabric.msp.msp import MSP
from hfc.util.crypto.crypto import ecies

_logger = logging.getLogger(__name__)
_logger.setLevel(logging.DEBUG)


class MSPManager(object):

    def __init__(self):
        self._msps = {}

    # TODO review with real values
    def loadMSPs(self, mspConfigs):
        method = 'loadMSPs'
        _logger.debug(f'{method} - start number of msps={len(mspConfigs)}')

        if not mspConfigs or not isinstance(mspConfigs, list):
            raise Exception('"mspConfigs" argument must be an array')

        for config in mspConfigs:
            if isinstance(config.type, int) or config.type != 0:
                raise Exception(f"MSP Configuration object type not supported: {config.type}")

            if not config.config:
                raise Exception('MSP Configuration object missing the payload in the "Config" property')

            fabricConfig = decode_fabric_MSP_config(config.config)

            if not fabricConfig['name']:
                raise Exception('MSP Configuration does not have a name')

            if not fabricConfig['root_certs']:
                raise Exception('MSP Configuration does not have any root certificates required for validating signing certificates')

            # TODO create a real newCryptoSuite module
            cs = ecies()

            orgs = []
            org_units = fabricConfig['organizational_unit_identifiers']
            if org_units:
                for org_unit in org_units:
                    org_id = org_unit['organizational_unit_identifier']
                    _logger.debug(f'{method} - found org of :: {org_id}')
                    orgs.append(org_id)

            newMSP = MSP({
                'rootCerts': fabricConfig['root_certs'],
                'intermediateCerts': fabricConfig['intermediate_certs'],
                'admins': fabricConfig['admins'],
                'id': fabricConfig['name'],
                'orgs': orgs,
                'cryptoSuite': cs,
                'tls_root_certs': fabricConfig['tls_root_certs'],
                'tls_intermediate_certs': fabricConfig['tls_intermediate_certs']
            })

            _logger.debug(f'{method} - found msp={newMSP.id}')
            self._msps[fabricConfig['name']] = newMSP

    def addMSP(self, config):
        if not config['cryptoSuite']:
            config['cryptoSuite'] = ecies() # TODO rework

        msp = MSP(config)
        _logger.debug(f'addMSP - msp={msp.id}')
        self._msps[msp.id] = msp
        return msp

    def getMSPs(self):
        return self._msps

    def getMSP(self, id):
        return self._msps[id]

    def deserializeIdentity(self, serializedIdentity):
        sid = decode_identity(serializedIdentity)
        mspid = sid['mspid']
        msp = self._msps[mspid]

        if not msp:
            raise Exception(f'Failed to locate an MSP instance matching the requested id "{mspid}" in the deserialized identity')

        return msp.deserializeIdentity(serializedIdentity)
