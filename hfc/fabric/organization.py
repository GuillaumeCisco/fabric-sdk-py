import logging


_logger = logging.getLogger(__name__)


class Organization(object):
    def __init__(self, name, mspid):
        _logger.debug('Organization.const')


        if not name:
            raise Exception('Missing name parameter')
        if not mspid:
            raise Exception('Missing mspid parameter')

        self._name = name
        self._mspid = mspid
        self._peers = []
        self._certificateAuthorities = []
        self._adminPrivateKeyPEM = None
        self._adminCertPEM = None

    @property
    def name(self):
        return self._name

    @property
    def mspid(self):
        return self._mspid

    def addPeer(self, peer):
        self._peers.append(peer)

    def getPeers(self):
        return self._peers

    def addCertificateAuthority(self, certificateAuthority):
        self._certificateAuthorities.append(certificateAuthority)

    def getCertificateAuthorities(self):
        return self._certificateAuthorities

    def setAdminPrivateKey(self, adminPrivateKeyPEM):
        self._adminPrivateKeyPEM = adminPrivateKeyPEM

    def getAdminPrivateKey(self):
        return self._adminPrivateKeyPEM

    def setAdminCert(self, adminCertPEM):
        self._adminCertPEM = adminCertPEM

    def getAdminCert(self):
        return self._adminCertPEM

    def __str__(self):
        peers = ', '.join([str(peer) for peer in self._peers])
        cas = ', '.join([str(ca) for ca in self._certificateAuthorities])

        return f'Organization {self._name}, mspid: {self._mspid}, peers {peers}, certificateAuthorities {cas}'

