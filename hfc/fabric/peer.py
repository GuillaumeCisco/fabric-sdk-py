import logging

import aiogrpc

from hfc.fabric.remote import Remote
from hfc.protos.discovery import protocol_pb2_grpc
from hfc.protos.peer import peer_pb2_grpc, events_pb2_grpc
from hfc.util.utils import stream_envelope

_logger = logging.getLogger(__name__)


class Peer(Remote):
    def __init__(self, url, opts=None):

        super(Peer, self).__init__(url, opts)

        _logger.debug(f'Peer.const - url: {url} timeout: {self._request_timeout} name: {self.name}')

        self._endorser_client = None
        self._discovery_client = None
        self._event_client = None

        self._createClients()

    def _createClients(self):
        if not self._endorser_client:
            _logger.debug(f'_createClients - create peer endorser connection {self._endpoint.addr}')
            if self._endpoint.creds is None:
                self._endorser_channel = aiogrpc.insecure_channel(self._endpoint.addr, self._options)
            else:
                self._endorser_channel = aiogrpc.secure_channel(self._endpoint.addr, self._endpoint.creds, self._options)
            self._endorser_client = peer_pb2_grpc.EndorserStub(self._endorser_channel)
        if not self._discovery_client:
            _logger.debug(f'_createClients - create peer discovery connection {self._endpoint.addr}')
            if self._endpoint.creds is None:
                self._discovery_channel = aiogrpc.insecure_channel(self._endpoint.addr, self._options)
            else:
                self._discovery_channel = aiogrpc.secure_channel(self._endpoint.addr, self._endpoint.creds, self._options)
            self._discovery_client = protocol_pb2_grpc.DiscoveryStub(self._discovery_channel)
        if not self._event_client:
            _logger.debug(f'_createClients - create peer event connection {self._endpoint.addr}')
            if self._endpoint.creds is None:
                self._event_channel = aiogrpc.insecure_channel(self._endpoint.addr, self._options)
            else:
                self._event_channel = aiogrpc.secure_channel(self._endpoint.addr, self._endpoint.creds, self._options)
            self._event_client = events_pb2_grpc.DeliverStub(self._event_channel)

    def close(self):
        if self._endorser_client:
            _logger.debug(f'close - closing peer endorser connection {self._endpoint.addr}')
            self._endorser_channel.close()
            self._endorser_client = None
        if self._discovery_client:
            _logger.debug(f'close - closing peer discovery connection {self._endpoint.addr}')
            self._discovery_channel.close()
            self._discovery_client = None
        if self._event_client:
            _logger.debug(f'close - closing peer event connection {self._endpoint.addr}')
            self._event_channel.close()
            self._event_client = None

    def send_proposal(self, proposal, timeout=None):

        _logger.debug('Send proposal')

        #TODO handle timeout

        if not proposal:
            raise Exception('Missing proposal to send to peer')

        self._createClients()

        #TODO handle wait For Ready

        #TODO should we handle response?
        return self._endorser_client.ProcessProposal(proposal)

    def send_discovery(self, request, timeout=None):
        _logger.debug('Send discovery')

        # TODO handle timeout

        if not request:
            raise Exception('Missing request to send to peer discovery service')

        self._createClients()

        # TODO handle wait For Ready

        # TODO should we handle response?
        return self._discovery_client.Discover(request)

    def __str__(self):
        return f'Peer: {self._url}'

    # TODO remove after refacto, called in channel event hub
    def delivery(self, envelope, scheduler=None, filtered=True):
        _logger.debug(f'Send envelope {envelope}')

        if filtered:
            delivery_result = self._event_client.DeliverFiltered(stream_envelope(envelope))
        else:
            delivery_result = self._event_client.Deliver(stream_envelope(envelope))
        return delivery_result
