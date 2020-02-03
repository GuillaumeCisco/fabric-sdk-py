import logging
from _sha256 import sha256
from urllib.parse import urlparse

import aiogrpc

from hfc.util.utils import pem_to_der

MAX_SEND = 'grpc.max_send_message_length'
MAX_RECEIVE = 'grpc.max_receive_message_length'
MAX_SEND_V10 = 'grpc-max-send-message-length'
MAX_RECEIVE_V10 = 'grpc-max-receive-message-length'

USE_WAIT_FOR_READY = 'useWaitForReady'

_logger = logging.getLogger(__name__)

class Endpoint(object):

    #TODO verify pem, clientKey and clientCert are bytes
    def __init__(self, url, pem, clientKey, clientCert):

        purl = urlparse(url)

        if purl.scheme:
            self.protocol = purl.scheme

        if self.protocol == 'grpc':
            self.addr = purl.hostname
            self.creds = None
        elif self.protocol == 'grpcs':
            if not isinstance(pem, str):
                raise Exception('PEM encoded certificate is required.')

            if clientCert and clientKey:
                self.creds = aiogrpc.ssl_channel_credentials(pem, private_key=clientKey, certificate_chain=clientCert)
            else:
                self.creds = aiogrpc.ssl_channel_credentials(pem)
            self.addr = purl.hostname
        else:
            raise Exception(f'Invalid protocol: {self.protocol}. URLs must begin with grpc:// or grpcs://')

    def isTLS(self):
        return self.protocol == 'grpcs'

class Remote(object):

    def __init__(self, url, opts):

        self._options = {}

        # default
        self.useWaitForReady = False

        for key in opts:
            value = opts[key]

            # TODO handle with https://grpc.github.io/grpc/python/grpc.html#grpc.ClientCallDetails.wait_for_ready
            if key == USE_WAIT_FOR_READY:
                if isinstance(value, bool):
                    self.useWaitForReady = value
                continue
            if value and not isinstance(value, str) and not isinstance(value, int):
                raise Exception(f'invalid grpc option value:{key}-> ${value} expected string|integer')
            if key != 'pem' and key != 'ssl-target-name-override':
                self._options[key] = value

        self.clientCert = opts['clientCert']

        # connection options

        if 'ssl-target-name-override' in opts and isinstance(opts['ssl-target-name-override'], str):
            self._options['grpc.ssl_target_name_override'] = opts['ssl-target-name-override']
            self._options['grpc.default_authority'] = opts['ssl-target-name-override']

        if MAX_RECEIVE_V10 in opts:
            grpc_receive_max = opts[MAX_RECEIVE_V10]
        elif MAX_RECEIVE in opts:
            grpc_receive_max = opts[MAX_RECEIVE]
        else:
            grpc_receive_max = getConfigSetting(MAX_RECEIVE_V10)  # TODO
            if grpc_receive_max is None:
                grpc_receive_max = getConfigSetting(MAX_RECEIVE)

        if grpc_receive_max is None:
            grpc_receive_max = -1  # default is unlimited

        self._options[MAX_RECEIVE] = grpc_receive_max

        if MAX_SEND_V10 in opts:
            grpc_send_max = opts[MAX_SEND_V10]
        elif MAX_SEND in opts:
            grpc_send_max = opts[MAX_SEND]
        else:
            grpc_send_max = getConfigSetting(MAX_SEND_V10)  # TODO
            if grpc_send_max is None:
                grpc_send_max = getConfigSetting(MAX_SEND)

        if grpc_send_max is None:
            grpc_send_max = -1  # default is unlimited

        self._options[MAX_SEND] = grpc_send_max

        self._url = url
        self._endpoint = Endpoint(url, opts['pem'], opts['clientKey'], self.clientCert)

        if 'name' in opts:
            self._name = opts['name']
        else:
            split = url.split('//')
            self._name = split[1]

        if checkIntegerConfig(opts, 'request-timeout'): # TODO
            self._request_timeout = opts['request-timeout']
        else:
            self._request_timeout = getConfigSetting('request-timeout', 30000)  # default 30 seconds

        if checkIntegerConfig(opts, 'grpc-wait-for-ready-timeout'):  # TODO
            self._grpc_wait_for_ready_timeout = opts['grpc-wait-for-ready-timeout']
        else:
            self._grpc_wait_for_ready_timeout = getConfigSetting('grpc-wait-for-ready-timeout', 3000)  # default 3 seconds

        _logger.debug(f' ** Remote instance url: {self._url}, name: {self._name}, options loaded are:: {self._options}')

    @property
    def name(self):
        return self._name

    @property
    def url(self):
        return self._url

    def getClientCertHash(self):
        if self.clientCert:
            b64der = pem_to_der(self.clientCert)
            return sha256(b64der).digest()

        return None

    def getCharacteristics(self):
        characteristics = {
            'url': self._url,
            'name': self._name,
            'options': self._options,
        }

        if 'clientKey' in characteristics['options']:
            del characteristics['options']['clientKey']

        return characteristics

    def isTLS(self):
        return self._endpoint.isTLS()

    def __str__(self):
        return f'Remote: {self._url}'

