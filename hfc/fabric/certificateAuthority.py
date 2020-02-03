import logging


_logger = logging.getLogger(__name__)

# TODO rework with real method name
class certificateAuthority(object):

    def __init__(self, name, caname, url, connection_options, tlsCACerts, registrar):

        _logger.debug('CertificateAuthority.const')

        if not name:
            raise Exception('Missing name parameter')

        if not url:
            raise Exception('Missing url parameter')

        self._name = name

        if caname:
            self._caname = caname
        else:
            self._caname = name

        self._url = url
        self._connection_options = connection_options
        self._tlsCACerts = tlsCACerts
        self._registrar = registrar

        self.fabricCAServices = None

    @property
    def name(self):
        return self._name

    @property
    def caname(self):
        return self._caname

    @property
    def tlsCACerts(self):
        return self._tlsCACerts

    @property
    def registrar(self):
        return self._registrar

    @property
    def fabricCAServices(self):
        return self.fabricCAServices

    def register(self, req, registrar):
        return self.fabricCAServices.register(req, registrar)

    def enroll(self, req):
        return self.fabricCAServices.enroll(req)

    def reenroll(self, currentUser, attr_reqs):
        return self.fabricCAServices.reenroll(currentUser, attr_reqs)

    def revoke(self, request, registrar):
        return self.fabricCAServices.revoke(request, registrar)

    def generateCRL(self, request, registrar):
        return self.fabricCAServices.generateCRL(request, registrar)

    def newCertificateService(self):
        return self.fabricCAServices.newCertificateService()

    def newIdentityService(self):
        return self.fabricCAServices.newIdentityService()

    def newAffiliationService(self):
        return self.fabricCAServices.newAffiliationService()
