import logging

import aiogrpc

from hfc.fabric.remote import Remote
from hfc.protos.orderer import ab_pb2_grpc

from hfc.util.utils import stream_envelope

_logger = logging.getLogger(__name__)


class Orderer(Remote):

    def __init__(self, url, opts=None):

        super(Orderer, self).__init__(url, opts)

        _logger.debug(f'Orderer.const - url: {url} timeout: {self._request_timeout}')

        if self._endpoint.creds is None:
            self._channel = aiogrpc.insecure_channel(self._endpoint.addr, self._options)
        else:
            self._channel = aiogrpc.secure_channel(self._endpoint.addr, self._endpoint.creds, self._options)

        self._orderer_client = ab_pb2_grpc.AtomicBroadcastStub(self._channel)
        self._sendDeliverConnect = False

    def close(self):
        if self._channel:
            _logger.debug(f'close - closing orderer connection {self._endpoint.addr}')
            self._channel.close()

    def broadcast(self, envelope, timeout=None):
        # TODO handle timeout

        _logger.debug('broadcast - start')

        if not envelope or envelope == '':
            _logger.debug('broadcast ERROR - missing envelope')
            raise Exception('Missing data - Nothing to broadcast')

        # TODO handle waitForReady

        _logger.debug(f'Send envelope={envelope}')

        # this is a stream response
        return self._orderer_client.Broadcast(stream_envelope(envelope))

    def delivery(self, envelope):

        #TODO handle timeout

        _logger.debug('delivery - start')
        _logger.debug(f'Send envelope={envelope}')

        # TODO handle waitForReady

        # TODO should we handle block or status here?

        # this is a stream response
        return self._orderer_client.Deliver(stream_envelope(envelope))

    def __str__(self):
        return f'Orderer: {self._url}'

    #TODO remove after refacto
    def _handle_response_stream(self, responses):
        for response in responses:
            return response, self
