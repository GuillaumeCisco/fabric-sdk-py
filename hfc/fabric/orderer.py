import logging
from _sha256 import sha256

import aiogrpc

from hfc.fabric.remote import Remote
from hfc.protos.common import common_pb2
from hfc.protos.orderer import ab_pb2_grpc

from hfc.protos.utils import create_seek_info, create_seek_payload, create_envelope
from hfc.util.utils import current_timestamp, build_header, build_channel_header, stream_envelope, pem_to_der

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

        #TODO should we handle block or status here?

        # this is a stream response
        return self._orderer_client.Deliver(stream_envelope(envelope))

    def __str__(self):
        return f'Orderer: {self._url}'

    #TODO remove or deplace in channel
    def get_genesis_block(self, tx_context, channel_name):
        """ get the genesis block of the channel.
        Return: the genesis block in success or None in fail.
        """
        _logger.info("get genesis block - start")

        seek_info = create_seek_info(0, 0)

        kwargs = {}
        if self._client_cert_path:
            with open(self._client_cert_path, 'rb') as f:
                b64der = pem_to_der(f.read())
                kwargs['tls_cert_hash'] = sha256(b64der).digest()

        seek_info_header = build_channel_header(
            common_pb2.HeaderType.Value('DELIVER_SEEK_INFO'),
            tx_context.tx_id,
            channel_name,
            current_timestamp(),
            tx_context.epoch,
            **kwargs
        )

        seek_header = build_header(
            tx_context.identity,
            seek_info_header,
            tx_context.nonce)

        seek_payload_bytes = create_seek_payload(seek_header, seek_info)
        sig = tx_context.sign(seek_payload_bytes)
        envelope = create_envelope(sig, seek_payload_bytes)

        # this is a stream response
        return self.delivery(envelope)

    #TODO remove after refacto
    def _handle_response_stream(self, responses):
        for response in responses:
            return response, self
