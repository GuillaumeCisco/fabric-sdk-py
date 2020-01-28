# Copyright 281165273@qq.com. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
import json
import logging
import os
import re
from datetime import datetime

from hfc.fabric.block_decoder import BlockDecoder, decode_identity, decode_config_update, \
    decode_header, decode_proposal_response_payload, decode_chaincode_proposal_payload, decode_chaincode_action, \
    decode_config_envelope #, decode_collections_config
from hfc.fabric.transaction.tx_proposal_request import CC_TYPE_GOLANG, CC_INVOKE
from hfc.protos.common import common_pb2, configtx_pb2, ledger_pb2
from hfc.protos.orderer import ab_pb2
from hfc.protos.peer import chaincode_pb2, proposal_pb2, query_pb2, transaction_pb2
from hfc.protos.discovery import protocol_pb2
from hfc.protos.utils import create_cc_spec, create_seek_info, create_envelope
from hfc.util.utils import proto_str, current_timestamp, proto_b, \
    build_header, build_channel_header, \
    pem_to_der, build_proposal, sign_proposal, send_peers_proposal, \
    checkProposalRequest, checkInstallRequest
from ..msp.mspManager import MSPManager
from .channel_eventhub import ChannelEventHub
from ..orderer import Orderer
from ..peer import Peer
from ..policy import Policy
from ..sideDB import CollectionConfig
from ..transaction.transaction_id import TransactionID
from ...protos.gossip import message_pb2

SYSTEM_CHANNEL_NAME = "testchainid"

_logger = logging.getLogger(__name__)
_logger.setLevel(logging.DEBUG)


channel_count = 1

# TODO, rework
class DuplicatePeer(Exception):
    pass

class DuplicateOrderer(Exception):
    pass


class Channel(object):
    """The class represents of the channel.
    This is a client-side-only call. To create a new channel in the fabric
    call client._create_or_update_channel().
    """

    def __init__(self, name, clientContext):
        """Construct channel instance

        Args:
            client (object): fabric client instance, which provides
            operational context
            name (str): a unique name serves as the identifier of the channel
        """
        pat = "^[a-z][a-z0-9.-]*$"  # matching patter for regex checker
        if not re.match(pat, name):
            raise ValueError(f'Failed to create Channel. channel name should'
                             f' match Regex {pat}, but got {name}')

        if not clientContext:
            raise ValueError('Failed to create Channel. Missing requirement "clientContext" parameter.')

        self._name = name
        self._channel_peers = {}
        self._anchor_peers = []
        self._orderers = {}
        self._kafka_brokers = []
        self._clientContext = clientContext
        self._msp_manager = MSPManager()
        self._discovery_interests = {}
        self._discovery_results = None
        self._last_discover_timestamp = None
        self._use_discovery = os.environ.get('initialize-with-discovery', False)  # get from a file
        self._as_localhost = os.environ.get('discovery-as-localhost', True)  # get from a file
        self._discovery_cache_life = os.environ.get('discovery-cache-life', 300000)  # default is 5min, get from a file
        self._endorsement_handler = None
        self._commit_handler = None

        self._number = channel_count + 1

        _logger.debug(f'Constructed Channel instance:{self._number} name - {self._name}')

    def close(self):
        _logger.debug(f'close - closing connections')
        for channel_peer in self._channel_peers:
            channel_peer.close()

        for orderer in self._orderers:
            orderer.close()

    async def initialize(self, request):
        method = f'initialize{self._number}'
        _logger.debug(f'{method} - start channel: {self._name}')

        endorsement_handler_path = None
        commit_handler_path = None

        if request:
            _logger.debug(f"{method} - request.asLocalhost:{request['asLocalhost']}")
            _logger.debug(f"{method} - ConfigSetting-discovery-as-localhost:{self._as_localhost}")

            if request['configUpdate']:
                _logger.debug(f'{method} - have a configupdate')
                config_update = decode_config_update(request['configUpdate'])

                # TODO populate
                self._msp_manager.loadMSPs(config_update['msps'])
                self._anchor_peers = config_update['anchor_peers']
                return True
            else:
                use_discovery = self._use_discovery
                if request['discover']:
                    use_discovery = request['discover']
                as_localhost = self._as_localhost
                if request['asLocalhost']:
                    as_localhost = request['asLocalhost']
                cache_life_time = self._discovery_cache_life

                if use_discovery:
                    if isinstance(use_discovery, bool):
                        _logger.debug(f'{method} - user requested discover {use_discovery}')
                        self._use_discovery = use_discovery
                    else:
                        raise ValueError('Request parameter "discover" or config parameter "initialize-with-discovery"'
                                         ' must be boolean')
                if as_localhost:
                    if isinstance(as_localhost, bool):
                        _logger.debug(f'{method} - user requested discovery as localhost {as_localhost}')
                        self._as_localhost = as_localhost
                    else:
                        raise ValueError('Request parameter "asLocalhost" or config parameter "discovery-as-localhost"'
                                         ' must be boolean')
                if cache_life_time:
                    if isinstance(cache_life_time, int):
                        self._discovery_cache_life = cache_life_time
                    else:
                        raise ValueError('Config parameter "discovery-cache-life" must be number')

                if request['endorsementHandler']:
                    _logger.debug(f"{method} - user requested endorsementHandler {request['endorsementHandler']}")
                    endorsement_handler_path = request['endorsementHandler']

                if request['commitHandler']:
                    _logger.debug(f"{method} - user requested commitHandler {request['commitHandler']}")
                    commit_handler_path = request['commitHandler']

        self._endorsement_handler = await self._build_handler(endorsement_handler_path, 'endorsement-handler')
        self._commit_handler = await self._build_handler(commit_handler_path, 'commit-handler')

        try:
            results = await self._initialize(request)
        except Exception as e:
            _logger.debug(f'Problem with the initialize :: {e}')
            raise
        else:
            return results

    def _initialize(self, request):
        method = '_initialize'
        _logger.debug(f'{method} - start')

        self.__discovery_results = None
        self._last_discover_timestamp = None
        self._last_refresh_request = request.copy()
        target_peers = []

        if request and 'target' in request:
            target_peers.append(request['target'])
        if request and isinstance(request['targets'], list):
            target_peers += request['targets']

        if len(target_peers) == 0:
            if self._use_discovery:
                target_peers = self._getTargets(None, 'discover', True)
            else:
                target_peers = self._getTargets(None, 'all', True)

        final_error = None
        for target_peer in target_peers:
            try:
                _logger.debug(f'{method} - target peer {target_peer} starting')
                if self._use_discovery:
                    _logger.debug(f'{method} - starting discovery')
                    target_peer = self._getTargetForDiscovery(target_peer)

                    discover_request = {
                        'target': target_peer,
                        'config': True
                    }

                    discovery_results = await self._discover(discover_request)
                    if discovery_results['msps']:
                        self._buildDiscoveryMSPs(discovery_results)
                    else:
                        raise ValueError('No MSP information found')

                    if discovery_results['orderers']:
                        self._buildDiscoveryOrderers(discovery_results, discovery_results['msps'], discover_request)

                    if discovery_results['peers_by_org']:
                        self._buildDiscoveryPeers(discovery_results, discovery_results['msps'], discover_request)

                    discovery_results['endorsement_plans'] = []

                    interests = []
                    plan_ids = []
                    for plan_id, interest in self._discovery_interests.items():
                        _logger.debug(f'{method} - have interest of: {plan_id}')
                        plan_ids.append(plan_id)
                        interests.append(interest)

                    for i in plan_ids:
                        plan_id = plan_ids[i]
                        interest = interests[i]

                        discover_request = {
                            'target': target_peer,
                            'interests': [interest]
                        }

                        try:
                            discover_interest_results = await self._discover(discover_request)
                            if discover_interest_results \
                                and 'endorsement_plans' in discover_interest_results \
                                and discover_interest_results['endorsement_plans'][0]:
                                plan = self._buildDiscoveryEndorsementPlan(discover_interest_results, plan_id,
                                                                           discovery_results['msps'], discover_request)
                                discovery_results['endorsement_plans'].append(plan)
                                _logger.debug(f'{method} - Added an endorsement plan for {plan_id}')
                            else:
                                _logger.debug(f'{method} - Not adding an endorsement plan for {plan_id}')
                        except Exception as e:
                            _logger.debug(f'{method} - trying to get a plan for plan {plan_id} :: interest:{interest}'
                                          f' error:{e}')

                    discovery_results['timestamp'] = datetime.utcnow()
                    self._discovery_results = discovery_results
                    self._last_discover_timestamp = discovery_results['timestamp']

                    return discovery_results
                else:
                    target_peer = self._getFirstAvailableTarget(target_peer)
                    config_envelope = await self.getChannelConfig(target_peer)
                    _logger.debug(f'{method} - got config envelope from getChannelConfig :: {config_envelope}')
                    config_items = decode_config_envelope(config_envelope)
                    return config_items
            except Exception as e:
                _logger.error(str(e))
                final_error = e

            _logger.debug(f'{method} - target peer {target_peer} failed {final_error}')

        if final_error:
            raise Exception(final_error)
        else:
            raise ValueError('Initialization failed to complete')

    def _buildDiscoveryMSPs(self, discovery_results):
        method = '_buildDiscoveryMSPs'
        _logger.debug(f'{method} - build msps')

        for msp_name in discovery_results['msps']:
            msp = discovery_results['msps'][msp_name]
            config = {
                'rootCerts': msp['rootCerts'],
                'intermediateCerts': msp['intermediateCerts'],
                'admins': msp['admins'],
                'cryptoSuite': self._clientContext._cryptoSuite,
                'id': msp['id'],
                'orgs': msp['orgs'],
                'tls_root_certs': msp['tls_root_certs'],
                'tls_intermediate_certs': msp['tls_intermediate_certs']
            }
            self._msp_manager.addMSP(config)

    def _buildDiscoveryOrderers(self, discovery_results, msps, discover_request):
        method = '_buildDiscoveryOrderers'
        _logger.debug(f'{method} - build orderers')

        for msp_id in discovery_results['orderers']:
            _logger.debug(f'{method} - orderers msp:{msp_id}')
            endpoints = discovery_results['orderers'][msp_id]['endpoints']
            for endpoint in endpoints:
                _logger.debug(f'{method} - orderer mspid:{msp_id} endpoint:{endpoint.host}:{endpoint.port}')
                endpoint['name'] = self._buildOrdererName(
                    msp_id,
                    endpoint.host,
                    endpoint.port,
                    msps,
                    discover_request
                )

    def _buildDiscoveryPeers(self, discovery_results, msps, discover_request):
        method = '_buildDiscoveryPeers'
        _logger.debug(f'{method} - build peers')

        for msp_id in discovery_results['peers_by_org']:
            _logger.debug(f'{method} - peers msp:{msp_id}')
            peers = discovery_results['peers_by_org'][msp_id]['peers']
            for peer in peers:
                for chaincode in peer['chaincodes']:
                    interest = self._buildDiscoveryInterest(chaincode['name'])
                    plan_id = json.dumps(interest)
                    _logger.debug(f'{method} - looking at adding plan_id of {plan_id}')
                    self._discovery_interests[plan_id] = interest
                    _logger.debug(f'{method} - adding new interest of single chaincode :: {plan_id}')

                peer['name'] = self._buildPeerName(
                    peer['endpoint'],
                    peer['mspid'],
                    msps,
                    discover_request
                )
                _logger.debug(f'{method} -%s - peer:{peer}')

    def _buildDiscoveryEndorsementPlan(self, discovery_results, plan_id, msps, discover_request):
        method = '_buildDiscoveryEndorsementPlan'
        _logger.debug(f'{method} - build endorsement plan for {plan_id}')

        endorsement_plan = discovery_results['endorsment_plans'][0]
        endorsement_plan['plan_id'] = plan_id
        for group_name in endorsement_plan['groups']:
            _logger.debug(f'{method} - endorsing peer group {group_name}')
            peers = endorsement_plan['groups'][group_name]['peers']
            for peer in peers:
                peer['name'] = self._buildPeerName(
                    peer['endpoint'],
                    peer['mspid'],
                    msps,
                    discover_request
                )
                _logger.debug(f'{method} -%s - peer:{peer}')

        return endorsement_plan

    async def getDiscoveryResults(self, endorsement_hints):
        method = 'getDiscoveryResults'
        _logger.debug(f'{method} - start')

        if self._use_discovery:
            have_new_interests = self._merge_hints(endorsement_hints)
            allowed_age = self._discovery_cache_life
            now = datetime.utcnow()
            if have_new_interests or now - self._last_discover_timestamp > allowed_age:
                _logger.debug(f'{method} - need to refresh :: have_new_interests {have_new_interests}')
                await self.refresh()

            _logger.debug(f'{method} - returning results')
            return self._discovery_results
        else:
            _logger.debug('No discovery results to return')
            # not working with discovery or we have not been initialized
            raise ValueError('This Channel has not been initialized or not initialized with discovery support')

    async def getEndorsementPlan(self, endorsement_hint):
        method = 'getEndorsementPlan'
        _logger.debug(f'{method} - start - {endorsement_hint}')

        endorsement_plan = None
        discovery_results = await self.getDiscoveryResults(endorsement_hint)
        plan_id = json.dumps(endorsement_hint)
        _logger.debug(f'{method} - looking at plan_id of {plan_id}')
        if discovery_results and 'endorsement_plans' in discovery_results:
            for plan in discovery_results['endorsement_plans']:
                if plan['plan_id'] == plan_id:
                    endorsement_plan = plan
                    _logger.debug(f'{method} - found plan in known plans ::{plan_id}')
                    break

        if endorsement_plan:
            return json.loads(json.dumps(endorsement_plan))
        else:
            _logger.debug(f'{method} - plan not found in known plans')
            return None

    async def refresh(self):
        method = 'refresh'
        _logger.debug(f'{method} - using last initialize settings')

        try:
            results = await self._initialize(self._last_refresh_request)
        except Exception as e:
            _logger.error(f'{method} - failed:{e}')
        else:
            return results

    def getOrganizations(self):
        method = 'getOrganizations'
        _logger.debug(f'{method} - start')

        msps = self._msp_manager.getMSPSs()
        mspIds = msps.keys()
        orgs = [{'id': mspId} for mspId in mspIds]
        _logger.debug(f'{method} - orgs::{orgs}')
        return orgs

    def setMSPManager(self, msp_manager):
        self._msp_manager = msp_manager

    def getMSPManager(self):
        return self._msp_manager

    def addPeer(self, peer, mspid, roles, replace):
        name = peer.name
        check = name in self._channel_peers

        if check:
            if replace:
                _logger.debug(f'/n removing old peer  --name: {name} --URL: {peer.url}')
                self.removePeer(self._channel_peers[name])
            else:
                msg = f'Peer {name} already exists'
                _logger.error(msg)
                raise DuplicatePeer(msg)

        _logger.debug(f'adding a new peer  --name: {name} --URL: {peer.url}')

        channel_peer = ChannelPeer(mspid, self, peer, roles)
        self._channel_peers[name] = channel_peer

    def removePeer(self, peer):
        del self._channel_peers[peer.name]

    def getPeer(self, name):
        channel_peer = self._channel_peers[name]

        if not channel_peer:
            raise ValueError(f'Peer with name "{name}" not assigned to this channel')

        return channel_peer

    def getChannelPeer(self, name):
        return self.getPeer(name)

    def getPeers(self):
        _logger.debug(f'getPeers - list size: {len(self._channel_peers)}')
        return self._channel_peers

    def getChannelPeers(self):
        return self.getPeers()

    def addOrderer(self, orderer, replace):
        name = orderer.name
        check = name in self._orderers

        if check:
            if replace:
                self.removeOrderer(self._orderers[name])
            else:
                msg = f'Peer {name} already exists'
                _logger.error(msg)
                raise DuplicateOrderer(msg)

        self._orderers[name] = orderer

    def removeOrderer(self, orderer):
        del self._orderers[orderer.name]

    def getOrderer(self, name):
        orderer = self._orderers[name]

        if not orderer:
            raise ValueError(f'Orderer with name "{name}" not assigned to this channel')

        return orderer

    def getOrderers(self):
        _logger.debug(f'getOrderers - list size: {len(self._orderers)}')
        return self._orderers

    def newChannelEventHub(self, peer, requestor):
        _peer = None
        if peer:
            peers = self._getTargets(peer, 'eventSource', True)
            _peer = peers[0]

        return ChannelEventHub(self, _peer, requestor)

    def getChannelEventHub(self, name):
        if not isinstance(name, str):
            raise ValueError('"name" parameter must be a Peer name.')

        _channel_peer = self._channel_peers[name]
        if not _channel_peer:
            raise ValueError(f'Peer with name "{name}" not assigned to this channel')

        return _channel_peer.getChannelEventHub()

    def getChannelEventHubsForOrg(self, mspid):
        method = 'getOrganizations'
        _logger.debug(f'{method} - start')

        if not mspid:
            _mspid = self._clientContext.getMspid()
            _logger.debug(f'{method} - starting - using client mspid: {_mspid}')
        else:
            _mspid = mspid
            _logger.debug(f'{method} - starting - mspid: {_mspid}')

        channel_event_hubs = []
        for channel_peer in self._channel_peers:
            if channel_peer.isInOrg(_mspid):
                if channel_peer.isInRole('eventSource'):
                    channel_event_hubs.append(channel_peer.getChannelEventHub())
                else:
                    _logger.debug(f'{method} - channel peer:{channel_peer.name} is not an event source')

        return channel_event_hubs

    def getPeersForOrg(self, mspid):
        method = 'getOrganizations'
        _logger.debug(f'{method} - start')

        _mspid = None
        if not mspid:
            _mspid = self._clientContext.getMspid()
            _logger.debug(f'{method} - starting - using client mspid: {_mspid}')
        else:
            _mspid = mspid
            _logger.debug(f'{method} - starting - mspid: {_mspid}')

        peers = []
        for channel_peer in self._channel_peers:
            if channel_peer.isInOrg(_mspid):
                peers.append(channel_peer)

        return peers

    def getGenesisBlock(self, request=None):
        method = 'getGenesisBlock'
        _logger.debug(f'{method} - start')

        if request is None:
            request = {}

        orderer = self._clientContext.getTargetOrderer(request.get('orderer'), self.getOrderers(), self._name)
        tx_id = request.get('txId')
        if not tx_id:
            signer = self._clientContext._getSigningIdentity(True)
            tx_id = TransactionID(signer, True)
        else:
            signer = self._clientContext._getSigningIdentity(tx_id.isAdmin())

        seekSpecifiedStart = ab_pb2.SeekSpecified()
        seekSpecifiedStart.number = 0
        seekStart = ab_pb2.SeekPosition()
        seekStart.specified.CopyFrom(seekSpecifiedStart)

        seekSpecifiedStop = ab_pb2.SeekSpecified()
        seekSpecifiedStop.number = 0
        seekStop = ab_pb2.SeekPosition()
        seekStop.specified.CopyFrom(seekSpecifiedStop)

        seek_info = ab_pb2.SeekInfo()
        seek_info.start.CopyFrom(seekStart)
        seek_info.stop.CopyFrom(seekStop)

        seek_info.behavior = ab_pb2.SeekInfo.SeekBehavior.Value('BLOCK_UNTIL_READY')

        seek_info_header = build_channel_header(
            common_pb2.HeaderType.Value('DELIVER_SEEK_INFO'),
            self._name,
            tx_id.transactionID,
            self._initial_epoch, # TODO check if tx_context.epoch, is better,
            None,
            current_timestamp(),
            self._clientContext.getClientCertHash()
        )

        seek_header = build_header(signer, seek_info_header, tx_id.nonce)
        seek_payload = common_pb2.Payload()
        seek_payload.header.CopyFrom(seek_header)
        seek_payload.data = seek_info.SerializeToString()

        signed_proposal = sign_proposal(signer, seek_payload)
        envelope = create_envelope(signed_proposal.signature, signed_proposal.proposal_bytes)

        return orderer.delivery(envelope)

    async def _discover(self, request):
        method = '_discover'
        _logger.debug(f'{method} - start')

        results = {}
        if not request:
            request = {}

        useAdmin = True # default
        if isinstance(request.get('useAdmin'), bool):
            useAdmin = request['useAdmin']

        target_peer = self._getTargetForDiscovery(request['target'])
        signer = self._clientContext._getSigningIdentity(useAdmin)  # TODO utils.create_serialized_identity(requestor)
        discovery_request = protocol_pb2.Request()

        authentication = protocol_pb2.AuthInfo()
        authentication.client_identity = signer.SerializeToString()
        cert_hash = self._clientContext.getClientCertHash(True)
        if cert_hash:
            authentication.setClientTlsCertHash(cert_hash)

        discovery_request.authentication.CopyFrom(authentication)
        queries = []

        if request['local']:
            query = protocol_pb2.Query()
            queries.append(query)
            local_peers = protocol_pb2.LocalPeerQuery()
            query.local_peers.CopyFrom(local_peers)
            _logger.debug(f'{method} - adding local peers query')

        if request['config']:
            query = protocol_pb2.Query()
            queries.append(query)
            query.channel = self._name

            config_query = protocol_pb2.ConfigQuery()
            query.config_query.CopyFrom(config_query)
            _logger.debug(f'{method} - adding config query')

            query = protocol_pb2.Query()
            queries.append(query)
            query.channel = self._name

            peer_query = protocol_pb2.PeerMembershipQuery()
            query.peer_query.CopyFrom(peer_query)
            _logger.debug(f'{method} - adding channel peers query')

        if request['interests'] and len(request['interests']) > 0:
            query = protocol_pb2.Query()
            queries.append(query)
            query.channel = self._name

            interests = []
            for interest in request['interests']:
                proto_interest = self._build_proto_cc_interest(interest)
                interests.append(proto_interest)

            cc_query = protocol_pb2.ChaincodeQuery()
            cc_query.interests.extend(interests)
            query.cc_query.CopyFrom(cc_query)
            _logger.debug(f'{method} - adding chaincodes/collection query')

        discovery_request.queries.extend(queries)

        signedProposal = sign_proposal(signer, discovery_request)
        signed_request = create_envelope(signedProposal.signature, signedProposal.proposal_bytes)

        response = await target_peer.send_discovery(signed_request)
        _logger.debug(f'{method} - processing discovery response')

        if response and 'results' in response:
            error_msg = None
            _logger.debug(f'{method} - parse discovery response')
            for index in response['results']:
                result = response['results'][index]
                if not result:
                    error_msg = 'Discover results are missing'
                    break
                elif result['result'] == 'error':
                    _logger.error(f"Channel:{self._name} received discovery error:{result['error']['content']}")
                    error_msg = result['error']['content']
                    break
                else:
                    _logger.debug(f'{method} - process results')
                    if 'config_result' in result:
                        config = self._processDiscoveryConfigResults(result['config_result'])
                        results['msps'] = config['msps']
                        results['orderers'] = config['orderers']
                    if 'members' in result:
                        if request.get('local') and index == '0':
                            results['local_peers'] = self._processDiscoveryMembershipResults(result['members'])
                        else:
                            results['peers_by_org'] = self._processDiscoveryMembershipResults(result['members'])

                    if 'cc_query_res' in result:
                        results['endorsement_plans'] = self._processDiscoveryChaincodeResults(result['cc_query_res'])

                    _logger.debug(f'{method} - completed processing results')

            if error_msg:
                raise ValueError(f'Channel {self._name} Discovery error: {error_msg}')
            else:
                return results
        else:
            # TODO handle correctly error
            if 'connectFailed' in response:
                _logger.error(f'Unable to get discovery results from peer {target_peer.url}')
                target_peer.close()
 
            raise ValueError('Discovery has failed to return results')

    def _processDiscoveryChaincodeResults(self, q_chaincodes):
        method = '_processDiscoveryChaincodeResults'
        _logger.debug(f'{method} - start')

        endorsement_plans = []
        if q_chaincodes and 'content' in q_chaincodes:
            if isinstance(q_chaincodes['content'], list):
                for index in q_chaincodes['content']:
                    q_endors_desc = q_chaincodes['content'][index]
                    endorsement_plan = {}
                    endorsement_plan['chaincode'] = q_endors_desc['chaincode']
                    endorsement_plans.append(endorsement_plan)

                    # GROUPS
                    endorsement_plan['groups'] = {}
                    for group_name in q_endors_desc['endorsers_by_groups']:
                        _logger.debug(f'{method} - found group: {group_name}')
                        group = {}
                        group['peers'] = self._processPeers(q_endors_desc['endorsers_by_groups'][group_name]['peers'])
                        endorsement_plan['groups'][group_name] = group

                    # LAYOUT
                    endorsement_plan['layouts'] = []
                    for index in q_endors_desc['layouts']:
                        q_layout = q_endors_desc['layouts'][index]
                        layout = {}
                        for group_name in q_layout['quantities_by_group']:
                            layout['group_name'] = q_layout['quantities_by_group'][group_name]
                        _logger.debug(f'{method} - layout: {layout}')
                        endorsement_plan['layouts'].append(layout)

        return endorsement_plans

    def _processDiscoveryConfigResults(self, q_config):
        method = '_processDiscoveryConfigResults'
        _logger.debug(f'{method} - start')

        config = {}
        if q_config:
            try:
                if q_config['msps']:
                    config['msps'] = {}
                    for id in q_config['msps']:
                        _logger.debug(f'{method} - found organization {id}')
                        q_msp = q_config['msps'][id]
                        msp_config = {
                            'id': id,
                            'orgs': q_msp['organizational_unit_identifiers'],
                            'rootCerts': byteToNormalizedPEM(q_msp['root_certs']), # TODO
                            'intermediateCerts': byteToNormalizedPEM(q_msp['intermediate_certs']), # TODO
                            'admins': byteToNormalizedPEM(q_msp['admins']),  # TODO
                            'tls_root_certs': byteToNormalizedPEM(q_msp['tls_root_certs']),  # TODO
                            'tls_intermediate_certs': byteToNormalizedPEM(q_msp['tls_intermediate_certs'])  # TODO
                        }
                        config['msps'] = msp_config
                if q_config['orderers']:
                    config['orderers'] = {}
                    for mspid in q_config['orderers']:
                        _logger.debug(f'{method} - found orderer org {mspid}')
                        config['orderers'][mspid] = {}
                        config['orderers']['endpoints'] = []
                        for index in q_config['orderers'][mspid]['endpoint']:
                            config['orderers'][mspid]['endpoints'].append(q_config['ordereres'][mspid]['endpoint'][index])
            except Exception as e:
                _logger.error(f'Problem with discovery config: {e}')

        return config

    def _processDiscoveryMembershipResults(self, q_members):
        method = '_processDiscoveryMembershipResults'
        _logger.debug(f'{method} - start')

        peers_by_org = {}
        if q_members and 'peers_by_org' in q_members:
            for mspid in q_members['peers_by_org']:
                _logger.debug(f'{method} - found org:{mspid}')
                peers_by_org[mspid] = {}
                peers_by_org[mspid]['peers'] = self._processPeers(q_members['peers_by_org'][mspid]['peers'])

        return peers_by_org

    def _processPeers(self, q_peers):
        method = '_processPeers'

        # TODO look a lot like decode_fabric_peers_info, please review

        peers = []
        for q_peer in q_peers:
            peer = {}

            # IDENTITY
            q_identity = decode_identity(q_peer.identity)
            peer['mspid'] = q_identity['msp_id']

            # MEMBERSHIP
            q_membership_message = message_pb2.GossipMessage()
            q_membership_message.ParseFromString(q_peer['membership_info']['payload'])
            peer['endpoint'] = q_membership_message.alive_msg.membership.endpoint
            _logger.debug(f"{method} - found peer : {peer['endpoint']}")

            # STATE
            if 'state_info' in q_peer:
                message_s = message_pb2.GossipMessage()
                message_s.ParseFromString(q_peer['state_info']['payload'])

                if message_s \
                    and message_s.state_info \
                    and message_s.state_info.properties \
                    and hasattr(message_s.state_info.properties, 'ledger_height'):
                    peer['ledger_height'] = int(message_s.state_info.properties.ledger_height)
                else:
                    _logger.debug(f'{method} - did not find ledger_height')
                    peer['ledger_height'] = 0

                _logger.debug(f"{method} - found ledger_height : {peer['ledger_height']}")
                peer['chaincodes'] = []
                for index in message_s.state_info.properties.chaincodes:
                    q_chaincode = message_s.state_info.properties.chaincodes[index]
                    chaincode = {}
                    chaincode['name'] = q_chaincode.nane
                    chaincode['version'] = q_chaincode.version
                    # TODO metadata ?
                    _logger.debug(f'{method} - found chaincode : {chaincode}')
                    peer['chaincodes'].append(chaincode)

            peers.append(peer)

        return peers

    def _buildOrdererName(self, msp_id, host, port, msps, discover_request):
        method = '_buildOrdererName'
        _logger.debug(f'{method} - start')

        name = f'{host}:{port}'
        url = self._buildUrl(host, port, discover_request)

        # TODO replace by a for/else
        found = None
        for orderer in self._orderers:
            if orderer.url == url:
                _logger.debug(f'{method} - found existing orderer {url}')
                found = orderer

        if not found:
            if msp_id in msps:
                _logger.debug(f'{method} - create a new orderer  {url}')
                found = Orderer(url, self._buildOptions(name, url, host, msps[msp_id]))
                self.addOrderer(found, True)
            else:
                raise ValueError('No TLS cert information available')

        return found.name

    def _buildPeerName(self, endpoint, msp_id, msps, discover_request):
        method = '_buildPeerName'
        _logger.debug(f'{method} - start')

        name = endpoint
        host_port = endpoint.split(':')
        url = self._buildUrl(host_port[0], host_port[1], discover_request)
        found = None

        # TODO replace by for/else
        for peer in self._channel_peers:
            if peer.url == url:
                _logger.debug(f'{method} - create a new peer  {url}')
                found = peer

        if not found:
            if msp_id in msps:
                _logger.debug(f'{method} - create a new peer  {url}')
                found = Peer(url, self._buildOptions(name, url, host_port[0], msps[msp_id]))
                self.addPeer(found, msp_id, None, None)
        else:
            raise ValueError('No TLS cert information available')

        return found.name

    def _buildUrl(self, hostname, port, discover_request):
        method = '_buildUrl'
        _logger.debug(f'{method} - start')

        t_hostname = hostname

        # endpoints may be running in containers on the local system
        if self._as_localhost:
            t_hostname = 'localhost'

        # If we connect to the discovery peer over TLS, any peers returned by
        # discovery should also use TLS. If we connect to the discovery peer
        # without TLS, then any peers returned by discovery should not use TLS.
        # A mixed set of TLS and non-TLS peers is unlikely but possible via the
        # override.

        # TODO review
        protocol = 'grpcs' if discover_request['target'].isTLS() else 'grpc'
        overrideProtocol = os.environ.get('override-discovery-protocol') # get from a config file
        if overrideProtocol:
            protocol = overrideProtocol

        url = f'{protocol}://{t_hostname}:{port}'

        return url

    def _buildOptions(self, name, url, host, msp):
        method = '_buildOptions'
        _logger.debug(f'{method} - start')

        caroots = self._buildTlsRootCerts(msp)
        opts = {
            'pem': caroots,
            'ssl-target-name-override': host,
            'name': name
        }

        opts = self._clientContext.buildConnectionOptions(opts)
        self._clientContext.addTlsClientCertAndKey(opts)

        return opts

    def _buildTlsRootCerts(self, msp):
        caroots = ''
        if 'tls_root_certs' in msp and msp['tls_root_certs']:
            caroots = caroots + msp['tls_root_certs']
        if 'tls_intermediate_certs' in msp and msp['tls_intermediate_certs']:
            caroots = caroots + msp['tls_intermediate_certs']
        
        return caroots
    
    def _merge_hints(self, endorsement_hints):
        method = '_merge_hints'
        _logger.debug(f'{method} - start')

        if not endorsement_hints:
            _logger.debug(f'{method} - no hint return false')
            return False

        results = False
        hints = endorsement_hints
        if not isinstance(endorsement_hints, list):
            hints = [endorsement_hints]

        for hint in hints:
            key = json.dumps(hint)
            value = self._discovery_interests.get(key)
            _logger.debug(f'{method} - key {key}')
            if value:
                _logger.debug(f'{method} - found interest exist {key}')
            else:
                _logger.debug(f'{method} - add new interest {key}')
                self._discovery_interests['key'] = hint
                results = True

        return results

    def _buildDiscoveryInterest(self, name, collections=None):
        method = '_buildDiscoveryInterest'
        _logger.debug(f'{method} - start')

        interest = {}
        interest['chaincodes'] = []
        chaincodes = self._buildDiscoveryChaincodeCall(name, collections)
        interest['chaincodes'].append(chaincodes)

        return interest

    def _buildDiscoveryChaincodeCall(self, name, collection_names):
        chaincode_call = {}
        if isinstance(name, str):
            chaincode_call['name'] = name
            if collection_names is not None:
                if isinstance(collection_names, list):
                    chaincode_call['collection_names'] = []
                    for name1 in collection_names:
                        if isinstance(name1, str):
                            chaincode_call['collection_names'].append(name)
                        else:
                            raise Exception('The collection name must be a string')
                else:
                    raise Exception('Collections names must be an array of strings')
        else:
            raise Exception('Chaincode name must be a string')

        return chaincode_call

    def joinChannel(self, request, timeout):
        method = 'joinChannel'
        _logger.debug(f'{method} - start')

        errorMsg = None

        if not request:
            errorMsg = 'Missing all required input request parameters'
        elif not 'txId' in request:
            errorMsg = 'Missing txId input parameter with the required transaction identifier'
        elif not 'block' in request:
            errorMsg = 'Missing block input parameter with the required genesis block'

        if errorMsg:
            _logger.error(f'{method} - error {errorMsg}')
            raise Exception(errorMsg)

        targets = self._getTargets(request['targets'], 'ALL_ROLES')
        signer = self._clientContext._getSigningIdentity(request['txId'].isAdmin())
        chaincode_input = chaincode_pb2.ChaincodeInput()
        chaincode_input.args.extend([proto_b("JoinChain"), request['block']])

        chaincode_id = chaincode_pb2.ChaincodeID()
        chaincode_id.name = proto_str("cscc")

        chaincodeSpec = create_cc_spec(chaincode_input, chaincode_id, 'GOLANG')

        channel_header = build_channel_header(
            common_pb2.HeaderType.Value('ENDORSER_TRANSACTION'),
            '',
            request['txId'].transactionID,
            None,
            'cscc',
            current_timestamp(),
            self._clientContext.getClientCertHash())

        header = build_header(signer, channel_header, request['txId'].nonce)
        proposal = build_proposal(chaincodeSpec, header)
        signed_proposal = sign_proposal(signer, proposal)

        return send_peers_proposal(targets, signed_proposal, timeout)

    async def getChannelConfig(self, target, timeout=None):
        method = 'getChannelConfig'
        _logger.debug(f'{method} - start for channel {self._name}')

        targets = self._getTargetForQuery(target)
        signer = self._clientContext._getSigningIdentity(True)
        tx_id = TransactionID(signer, True)
        request = {
            'targets': targets,
            'chaincodeId': 'cscc',
            'txId': tx_id,
            'signer': signer,
            'fcn': 'GetConfigBlock',
            'args': [self._name]
        }
        request['targets'] = self._getTargets(request['targets'], 'endorsingPeer')

        responses, _ = await Channel.send_transaction_proposal(request, self._name, self._clientContext, timeout)

        _logger.debug(f'{method} - results received')
        if responses and isinstance(responses, list):
            pplResponse = responses[0]
            # handle Error
            if pplResponse.status != 200:
                raise Exception(pplResponse)
            else:
                block = common_pb2.Block()
                block.ParseFromString(pplResponse.response.payload)
                envelope = common_pb2.Envelope()
                envelope.ParseFromString(block.data.data[0])
                payload = common_pb2.Payload()
                payload.ParseFromString(envelope.payload)
                config_envelope = configtx_pb2.ConfigEnvelope()
                config_envelope.ParseFromString(payload.data)
                return config_envelope

        raise Exception('Payload results are missing from the get channel config')

    async def getChannelConfigFromOrderer(self):
        method = 'getChannelConfig'
        _logger.debug(f'{method} - start for channel {self._name}')

        orderer = self._clientContext.getTargetOrderer(None, self.getOrderers(), self._name)

        signer = self._clientContext._getSigningIdentity(True)
        tx_id = TransactionID(signer, True)

        seekSpecifiedStart = ab_pb2.SeekNewest()
        seekStart = ab_pb2.SeekPosition()
        seekStart.specified.CopyFrom(seekSpecifiedStart)

        seekSpecifiedStop = ab_pb2.SeekNewest()
        seekStop = ab_pb2.SeekPosition()
        seekStop.specified.CopyFrom(seekSpecifiedStop)

        seek_info = ab_pb2.SeekInfo()
        seek_info.start.CopyFrom(seekStart)
        seek_info.stop.CopyFrom(seekStop)

        seek_info.behavior = ab_pb2.SeekInfo.SeekBehavior.Value('BLOCK_UNTIL_READY')

        seek_info_header = build_channel_header(
            common_pb2.HeaderType.Value('DELIVER_SEEK_INFO'),
            self._name,
            tx_id.transactionID,
            self._initial_epoch,  # TODO check if tx_context.epoch, is better,
            None,
            current_timestamp(),
            self._clientContext.getClientCertHash()  # TODO
        )

        seek_header = build_header(signer, seek_info_header, tx_id.nonce)
        seek_payload = common_pb2.Payload()
        seek_payload.header.CopyFrom(seek_header)
        seek_payload.data = seek_info.SerializeToString()

        signed_proposal = sign_proposal(signer, seek_payload)
        envelope = create_envelope(signed_proposal.signature, signed_proposal.proposal_bytes)

        # this is a stream response
        block = None
        stream = orderer.delivery(envelope)
        async for v in stream:
            if v.block is None or v.block == '':
                _logger.error(f'{method} - did not find latest block')
                raise Exception('Failed to retrieve latest block')
            block = v.block
            break
        block = BlockDecoder().decode(block.SerializeToString())

        _logger.error(f"{method} -  latest block is block number {block['header']['number']}")

        last_config = block['metadata']['metadata'][common_pb2.LAST_CONFIG]
        # TODO use protos LastConfig.decode

        tx_id = TransactionID(signer)
        # if not first block
        if 'index' in last_config['value']:
            seek_info = create_seek_info(last_config['value']['index'],
                                         last_config['value']['index'])
            seek_info_header = build_channel_header(
                common_pb2.HeaderType.Value('DELIVER_SEEK_INFO'),
                self._name,
                tx_id.transactionID,
                self._initial_epoch,  # TODO check if tx_context.epoch, is better,
                None,
                current_timestamp(),
                self._clientContext.getClientCertHash()  # TODO
            )
            seek_header = build_header(signer, seek_info_header, tx_id.nonce)
            seek_payload = common_pb2.Payload()
            seek_payload.header.CopyFrom(seek_header)
            seek_payload.data = seek_info.SerializeToString()

            signed_proposal = sign_proposal(signer, seek_payload)
            envelope = create_envelope(signed_proposal.signature, signed_proposal.proposal_bytes)

            block = None
            stream = orderer.delivery(envelope)
            async for v in stream:
                if v.block is None or v.block == '':
                    msg = "fail to get block"
                    _logger.error(msg)
                    raise Exception(msg)
                block = v.block
                break

            block = BlockDecoder().decode(block.SerializeToString())

            envelope = block['data']['data'][0]
            payload = envelope['payload']
            channel_header = payload['header']['channel_header']

            if channel_header['type'] != common_pb2.CONFIG:
                raise Exception(f'Block must be of type "CONFIG"'
                                f' ({common_pb2.CONFIG}), but got'
                                f' "{channel_header["type"]}" instead')

            config_envelope = payload['data']
            return config_envelope

    async def queryInfo(self, target, useAdmin):
        method = 'queryInfo'
        _logger.debug(f'{method} - start')

        targets = self._getTargetForQuery(target)
        signer = self._clientContext._getSigningIdentity(useAdmin)
        tx_id = TransactionID(signer, useAdmin)
        request = {
            'targets': targets,
            'chaincodeId': 'qscc',
            'txId': tx_id,
            'signer': signer,
            'fcn': 'GetChainInfo',
            'args': [self._name]
        }

        responses, _ = await Channel.send_transaction_proposal(request, self._name, self._clientContext, None)

        _logger.debug(f'{method} - results received')
        if responses and isinstance(responses, list):
            if len(responses) > 1:
                raise Exception('Too many results returned')
            pplResponse = responses[0]
            if pplResponse.response.status != 200:
                raise Exception(pplResponse.response.message)
            else:
                chain_info = ledger_pb2.BlockchainInfo()
                chain_info.ParseFromString(pplResponse.response.payload)
                return chain_info

        raise Exception('Payload results are missing from the query channel info')

    async def queryBlockByTxID(self, tx_id, target, useAdmin, skipDecode):
        method = 'queryBlockByTxID'
        _logger.debug(f'{method} - start')

        if not tx_id or not isinstance(tx_id, str):
            raise Exception('tx_id as string is required')

        args = [self._name, tx_id]
        targets = self._getTargetForQuery(target)
        signer = self._clientContext._getSigningIdentity(useAdmin)
        tx_id = TransactionID(signer, useAdmin)
        request = {
            'targets': targets,
            'chaincodeId': 'qscc',
            'txId': tx_id,
            'signer': signer, # TODO see if it still works by removing signer
            'fcn': 'GetBlockByTxID',
            'args': args
        }

        responses, _ = await Channel.send_transaction_proposal(request, self._name, self._clientContext, None)

        _logger.debug(f'{method} - results received')
        if responses and isinstance(responses, list):
            if len(responses) > 1:
                raise Exception('Too many results returned')
            pplResponse = responses[0]
            if pplResponse.response.status != 200:
                raise Exception(pplResponse.response.message)
            else:
                _logger.debug(f"queryBlockByTxID - response status: {pplResponse.response.status}")
                if skipDecode:
                    return pplResponse.response.payload
                else:
                    block = BlockDecoder().decode(pplResponse.response.payload)
                    _logger.debug(f"queryBlockByTxID - looking at block ::{block['header']['number']}")
                    return block

        raise Exception('Payload results are missing from the query')

    async def queryBlockByHash(self, blockHash, target, useAdmin, skipDecode):
        method = 'queryBlockByHash'
        _logger.debug(f'{method} - start')

        if not blockHash:
            raise Exception('Blockhash bytes are required')

        targets = self._getTargetForQuery(target)
        signer = self._clientContext._getSigningIdentity(useAdmin)
        tx_id = TransactionID(signer, useAdmin)
        request = {
            'targets': targets,
            'chaincodeId': 'qscc',
            'txId': tx_id,
            'signer': signer,
            'fcn': 'GetBlockByHash',
            'args': [self._name],
            'argbytes': blockHash
        }

        responses, _ = await Channel.send_transaction_proposal(request, self._name, self._clientContext, None)

        _logger.debug(f'{method} - results received')
        if responses and isinstance(responses, list):
            if len(responses) > 1:
                raise Exception('Too many results returned')
            pplResponse = responses[0]
            if pplResponse.response.status != 200:
                raise Exception(pplResponse.response.message)
            else:
                _logger.debug(f"queryBlockByHash - response status: {pplResponse.response.status}")
                if skipDecode:
                    return pplResponse.response.payload
                else:
                    block = BlockDecoder().decode(pplResponse.response.payload)
                    _logger.debug(f"queryBlockByHash - looking at block ::{block['header']['number']}")
                    return block

        raise Exception('Payload results are missing from the query')

    async def queryBlock(self, blockNumber, target, useAdmin, skipDecode):
        method = 'queryBlock'
        _logger.debug(f'{method} - start')

        if not(isinstance(blockNumber, int) and blockNumber >= 0):
            raise Exception('Block number must be a positive integer')

        block_number = str(blockNumber)

        targets = self._getTargetForQuery(target)
        signer = self._clientContext._getSigningIdentity(useAdmin)
        tx_id = TransactionID(signer, useAdmin)
        request = {
            'targets': targets,
            'chaincodeId': 'qscc',
            'txId': tx_id,
            'signer': signer,
            'fcn': 'GetBlockByNumber',
            'args': [self._name, block_number],
        }

        responses, _ = await Channel.send_transaction_proposal(request, self._name, self._clientContext, None)

        _logger.debug(f'{method} - results received')
        if responses and isinstance(responses, list):
            if len(responses) > 1:
                raise Exception('Too many results returned')
            pplResponse = responses[0]
            if pplResponse.response.status != 200:
                raise Exception(pplResponse.response.message)
            else:
                _logger.debug(f"queryBlock - response status: {pplResponse.response.status}")
                if skipDecode:
                    return pplResponse.response.payload
                else:
                    block = BlockDecoder().decode(pplResponse.response.payload)
                    _logger.debug(f"queryBlock - looking at block ::{block['header']['number']}")
                    return block

        raise Exception('Payload results are missing from the query')

    async def queryTransaction(self, tx_id, target, useAdmin, skipDecode):
        method = 'queryTransaction'
        _logger.debug(f'{method} - start transactionID {tx_id}')

        if not tx_id:
            raise Exception('Missing "tx_id" parameter')
        tx_id = str(tx_id)

        targets = self._getTargetForQuery(target)
        signer = self._clientContext._getSigningIdentity(useAdmin)
        txId = TransactionID(signer, useAdmin)
        request = {
            'targets': targets,
            'chaincodeId': 'qscc',
            'txId': txId,
            'signer': signer,
            'fcn': 'GetTransactionByID',
            'args': [self._name, tx_id],
        }

        responses, _ = await Channel.send_transaction_proposal(request, self._name, self._clientContext, None)

        _logger.debug(f'{method} - results received')
        if responses and isinstance(responses, list):
            if len(responses) > 1:
                raise Exception('Too many results returned')
            pplResponse = responses[0]
            if pplResponse.response.status != 200:
                raise Exception(pplResponse.response.message)
            else:
                _logger.debug(f"queryTransaction - response status: {pplResponse.response.status}")
                if skipDecode:
                    return pplResponse.response.payload
                else:
                    process_tx = BlockDecoder.decode_transaction(pplResponse.response.payload)
                    return process_tx

        raise Exception('Payload results are missing from the query')

    async def queryInstantiatedChaincodes(self, target, useAdmin):
        method = 'queryInstantiatedChaincodes'
        _logger.debug(f'{method} - start')

        targets = self._getTargetForQuery(target)
        signer = self._clientContext._getSigningIdentity(useAdmin)
        txId = TransactionID(signer, useAdmin)
        request = {
            'targets': targets,
            'chaincodeId': 'lscc',
            'txId': txId,
            'signer': signer,
            'fcn': 'getchaincodes',
            'args': [],
        }

        responses, _ = await Channel.send_transaction_proposal(request, self._name, self._clientContext, None)

        _logger.debug(f'{method} - results received')
        if responses and isinstance(responses, list):
            if len(responses) > 1:
                raise Exception('Too many results returned')
            pplResponse = responses[0]
            if pplResponse.response.status != 200:
                raise Exception(pplResponse.response.message)
            else:
                _logger.debug(f"queryInstantiatedChaincodes - response status: {pplResponse.response.status}")
                query_trans = query_pb2.ChaincodeQueryResponse()
                query_trans.ParseFromString(pplResponse.response.payload)
                _logger.debug(f"queryInstantiatedChaincodes - ProcessedTransaction.chaincodeInfo.length ::"
                              f" {len(query_trans['chaincodes'])}")
                for chaincode in query_trans['chaincodes']:
                    _logger.debug(f"queryInstantiatedChaincodes -name {chaincode['name']}, version {chaincode['version']}, path {chaincode['path']}")

                return query_trans

        raise Exception('Payload results are missing from the query')

    async def queryCollectionsConfig(self, options, useAdmin):
        method = 'queryCollectionsConfig'
        _logger.debug(f'{method} - start. options: {options}, useAdmin: {useAdmin}')

        if not options or 'chaincodeId' not in options or not isinstance(options['chaincodeId'], str):
            raise Exception('Missing required argument \'options.chaincodeId\' or \'options.chaincodeId\' is not of type string')

        targets = self._getTargetForQuery(options['target'])
        signer = self._clientContext._getSigningIdentity(useAdmin)
        txId = TransactionID(signer, useAdmin)
        request = {
            'targets': targets,
            'chaincodeId': 'lscc',
            'txId': txId,
            'signer': signer,
            'fcn': 'GetCollectionsConfig',
            'args': [options['chaincodeId']],
        }

        responses, _ = await Channel.send_transaction_proposal(request, self._name, self._clientContext, None)

        _logger.debug(f'{method} - results received')
        if responses and isinstance(responses, list):
            if len(responses) > 1:
                raise Exception('Too many results returned')
            pplResponse = responses[0]
            if pplResponse.response.status != 200:
                raise Exception(pplResponse.response.message)
            else:
                _logger.debug(f"{method} - response status: {pplResponse.response.status}")
                queryResponse = decode_collections_config(pplResponse.response.payload) # TODO
                _logger.debug(f"{method} - get {queryResponse} collection for chaincode {options['chaincodeId']} from peer")
                return queryResponse

        raise Exception('Payload results are missing from the query')

    def sendInstantiateProposal(self, request, timeout):
        return self._sendChaincodeProposal(request, 'deploy', timeout)

    def sendUpgradeProposal(self, request, timeout):
        return self._sendChaincodeProposal(request, 'upgrade', timeout)

    def _sendChaincodeProposal(self, request, command, timeout):
        errorMsg = None

        if not errorMsg:
            errorMsg = checkProposalRequest(request, True)
        if not errorMsg:
            errorMsg = checkInstallRequest(request)

        if errorMsg:
            _logger.error(f'_sendChaincodeProposal error {errorMsg}')
            raise Exception(errorMsg)

        peers = self._getTargets(request['targets'], 'endorsingPeer')

        if 'args' not in request or not request['args']:
                request['args'] = []

        # step 1: construct a ChaincodeSpec
        args = []

        if not 'fcn' in request or not request['fcn']:
            fcn = 'init'
        else:
            fcn = request['fcn']
        args.append(proto_b(request.fcn))

        for arg in request['args']:
            args.append(proto_b(arg))

        cc_id = chaincode_pb2.ChaincodeID()
        cc_id.name = request['chaincodeId']
        cc_id.version = request['chaincodeVersion']

        cc_input = chaincode_pb2.ChaincodeInput()
        cc_input.args.extend(args)
        cc_spec = create_cc_spec(cc_input, cc_id, request['chaincodeType'] or CC_TYPE_GOLANG)

        # step 2: construct the ChaincodeDeploymentSpec
        cc_dep_spec = chaincode_pb2.ChaincodeDeploymentSpec()
        cc_dep_spec.chaincode_spec.CopyFrom(cc_spec)

        signer = self._clientContext._getSigningIdentity(request['txId'].isAdmin())

        lcccSpec_args = [
            proto_b(command),
            proto_b(self._name),
            cc_dep_spec.SerializeToString(),
            '',
            proto_b('escc'),
            proto_b('vscc'),
        ]
 
        if 'endorsement-policy' in request:
            lcccSpec_args[3] = self._buildEndorsementPolicy(request['endorsement-policy'])

        if 'collections_config' in request:
            collectionConfigPackage = CollectionConfig.buildCollectionConfigPackage(request['collections-config'])
            lcccSpec_args.append(collectionConfigPackage.SerializeToString())

        # client can specify the escc and vscc names
        if 'escc' in request and isinstance(request['escc'], str):
            lcccSpec_args[4] = proto_b(request['escc'])
        if 'vscc' in request and isinstance(request['vscc'], str):
            lcccSpec_args[5] = proto_b(request['vscc'])

        # construct the invoke spec

        invoke_cc_id = chaincode_pb2.ChaincodeID()
        invoke_cc_id.name = proto_str('lscc')

        invoke_input = chaincode_pb2.ChaincodeInput()
        invoke_input.args.extend(lcccSpec_args)

        lcccSpec = chaincode_pb2.ChaincodeInvocationSpec()
        lcccSpec.chaincode_spec.CopyFrom(create_cc_spec(invoke_input, invoke_cc_id, request['chaincodeType'] or CC_TYPE_GOLANG))

        extension = proposal_pb2.ChaincodeHeaderExtension()
        extension.chaincode_id.name = proto_str('lscc')
        channel_header = build_channel_header(
            common_pb2.ENDORSER_TRANSACTION,
            self._name,
            request['txId'].transacationID,
            None,
            'lscc',
            current_timestamp(),
            self._clientContext.getClientCertHash()
        )

        header = build_header(signer, channel_header, request['txId'].nonce)
        proposal = build_proposal(lcccSpec, header, request['transientMap'])
        signed_proposal = sign_proposal(signer, proposal)

        responses = await send_peers_proposal(peers, signed_proposal, timeout)
        return responses, proposal

    async def sendTransactionProposal(self, request, timeout):
        method = 'sendTransactionProposal'
        _logger.debug(f'{method} - start')

        errorMsg = checkProposalRequest(request, True)
        if errorMsg:
            raise Exception('Missing "args" in Transaction proposal request')

        # convert any names into peer objects or if empty find all
        # endorsing peers added to this channel if discovery is off
        if not self._use_discovery or 'targets' in request:
            _logger.debug(f'{method} - checking for targets')
            request['targets'] = self._getTargets(request['targets'], 'endorsingPeer')
        else:
            _logger.debug(f'{method} - discovery is on and no targets')

        if self._endorsement_handler:
            _logger.debug(f'{method} - running with endorsement handler')
            proposal = Channel._buildSignedProposal(request, self._name, self._clientContext)

            endorsement_hint = request['endorsement_hint']
            if not endorsement_hint and 'chaincodeId' in request:
                endorsement_hint = self._buildDiscoveryInterest(request['chaincodeId'])

            _logger.debug(f'{method} - endorse with hint {endorsement_hint}')

            params = {
                'request': request,
                'signed_proposal': proposal['signed'],
                'timeout': timeout,
                'endorsement_hint': endorsement_hint,
                'use_discovery': self._use_discovery
            }

            responses = await self._endorsement_handler.endorse(params)

            return responses, proposal['source']
        else:
            _logger.debug(f'{method} - running without endorsement handler')
            return Channel.send_transaction_proposal(request, self._name, self._clientContext, timeout)

    @staticmethod
    async def send_transaction_proposal(request, channelId, client_context, timeout):
        method = 'send_transaction_proposal'
        _logger.debug(f'{method} - start')

        errorMsg = checkProposalRequest(request, True)

        if not errorMsg:
            if 'args' not in request:
                errorMsg = 'Missing "args" in Transaction proposal request'
            elif 'targets' not in request and len(request['targets']) < 1:
                errorMsg = 'Missing peer objects in Transaction proposal'

        if errorMsg:
            _logger.error(f'{method} - error {errorMsg}')
            raise Exception(errorMsg)

        proposal = Channel._buildSignedProposal(request, channelId, client_context)
        responses = await send_peers_proposal(request['targets'], proposal['signed'], timeout) # TODO will maybe be await asyncio.gather(*responses)
        return responses, proposal['source']

    @staticmethod
    def _buildSignedProposal(request, channelId, client_context):
        method = '_buildSignedProposal'
        _logger.debug(f'{method} - start')

        args = []
        if request['fcn']:
            args.append(proto_b(request['fcn']))
        else:
            args.append(proto_b(CC_INVOKE))

        for arg in request['args']:
            if isinstance(arg, bytes):
                args.append(arg)
            else:
                args.append(proto_b(arg))

        if 'argbytes' in request and request['argbytes']:
            args.append(request['argbytes'])

        invokeSpec = {
            'type': chaincode_pb2.ChaincodeSpec.Type.Value(CC_TYPE_GOLANG),
            'chaincode_id': {'name': request['chaincodeId']},
            'input': {'args': args}
        }

        if 'signer' in request and request['signer']:
            signer = request['signer']
        else:
            signer = client_context._getSigningIdentity(request['txId'].isAdmin())

        channel_header = build_channel_header(
            common_pb2.ENDORSER_TRANSACTION,
            channelId,
            request['txId'].transactionID,
            None,
            request['chaincodeId'],
            current_timestamp(),
            client_context.getClientCertHash())

        header = build_header(signer, channel_header, request['txId'].nonce)
        proposal = build_proposal(invokeSpec, header, request['transientMap'])
        signed_proposal = sign_proposal(signer, proposal)

        return {'signed': signed_proposal, 'source': proposal}

    async def sendTransaction(self, request, timeout):
        method = 'sendTransaction'
        _logger.debug(f'{method} - start :: channel {self}')

        if not request:
            raise Exception('Missing input request object on the transaction request')

        if 'proposalResponses' not in request:
            raise Exception('Missing "proposalResponses" parameter in transaction request')
        if 'proposal' not in request:
            raise Exception('Missing "proposal" parameter in transaction request')

        proposalResponses = request['proposalResponses']
        chaincodeProposal = request['payload']

        endorsments = []
        if not isinstance(proposalResponses, list):
            proposalResponses = [proposalResponses]

        for proposalResponse in proposalResponses:
            if proposalResponse and proposalResponse.response and proposalResponse.response.status == 200:
                endorsments.append(proposalResponse.endorsment)

        if len(endorsments) < 1:
            _logger.error('sendTransaction - no valid endorsements found')
            raise Exception('no valid endorsements found')

        proposalResponse = proposalResponses[0]

        use_admin_signer = False
        if 'txId' in request:
            use_admin_signer = request['txId'].isAdmin()

        envelope = Channel.buildEnvelope(self._clientContext, chaincodeProposal, endorsments, proposalResponse, use_admin_signer)

        if self._commit_handler:
            param_request = request.copy()
            if param_request['orderer']:
                param_request['orderer'] = self._clientContext.getTargetOrderer(param_request['orderer'], self.getOrderers(), self._name)

            params = {
                'signed_envelope': envelope,
                'request': param_request,
                'timeout': timeout
            }
            return self._commit_handler(params)
        else:
            orderer = self._clientContext.getTargetOrderer(request['orderer'], self.getOrderers(), self._name)
            return orderer.sendBroadcast(envelope, timeout)

    def generateUnsignedProposal(self, request, mspId, certificate, admin):
        method = 'generateUnsignedProposal'
        _logger.debug(f'{method} - start')

        errorMsg = checkProposalRequest(request, False)
        if errorMsg:
            _logger.error(f'{method} - error {errorMsg}')
            raise Exception(errorMsg)

        if not isinstance(request['args'], list):
            _logger.error(f"{method} - Parameter \"args\" in transaction proposal request must be an array but was {type(request['args'])}")
            raise Exception(errorMsg)

        if 'fcn' not in request:
            functionName = 'invoke'
        else:
            functionName = request['fcn']

        _logger.debug(f'{method} - adding function arg: {functionName}')
        args = [proto_str(functionName)]
        for arg in request['args']:
            _logger.debug(f'{method} -  adding arg {arg}')
            if isinstance(arg, bytes):
                args.append(arg)
            else:
                args.append(proto_b(arg))
        # special case to support the bytes argument of the query by hash
        if 'argbytes' in request:
            _logger.debug(f'{method} - adding the argument :: argbytes')
            args.append(request['argbytes'])
        else:
            _logger.debug(f'{method} - not adding the argument :: argbytes')

        invokeSpec = {
            'type': chaincode_pb2.ChaincodeSpec.Type.Value(CC_TYPE_GOLANG),
            'chaincode_id': {'name': request['chaincodeId']},
            'input': {'args': args}
        }

        identity = Identity(certificate, None, mspId) # TODO
        txId = TransactionID(identity, admin)
        channel_header = build_channel_header(
            common_pb2.ENDORSER_TRANSACTION,
            self._name,
            txId.transactionID,
            None,
            request['chaincodeId'],
            current_timestamp(),
            self._clientContext.getClientCertHash())

        header = build_header(identity, channel_header, txId.nonce)
        proposal = build_proposal(invokeSpec, header, request['transientMap'])
        return {'proposal': proposal, 'txId': txId}

    async def sendSignedProposal(self, request, timeout):
        return Channel.send_signed_proposal(request, timeout)

    @staticmethod
    async def send_signed_proposal(request, timeout):
        responses = await send_peers_proposal(request['targets'], request['signedProposal'], timeout)
        return responses

    def generateUnsignedTransaction(self, request):
        method = 'generateUnsignedTransaction'
        _logger.debug(f'{method} - start :: channel {self._name}')

        if not request:
            raise Exception('Missing input request object on the generateUnsignedTransaction() call')

        if not isinstance(request['proposalResponses'], list):
            raise Exception(f"\"proposalResponses\" parameter in transaction request must be an array but was {request['proposalResponses']}")
        if 'proposal' not in request:
            raise Exception('Missing "proposal" parameter in transaction request')

        proposalResponses = request['proposalResponses']
        chaincodeProposal = request['proposal']

        endorsments = []
        for proposalResponse in proposalResponses:
            if proposalResponse and proposalResponse.response and proposalResponse.response.status == 200:
                endorsments.append(proposalResponse.endorsment)

        if len(endorsments) < 1:
            _logger.error('sendTransaction - no valid endorsements found')
            raise Exception('no valid endorsements found')

        proposalResponse = proposalResponses[0]

        proposal = ChannelHelper.buildTransactionProposal( # TODO
            chaincodeProposal,
            endorsments,
            proposalResponse
        )

        return proposal

    def sendSignedTransaction(self, request, timeout):
        signed_envelope = create_envelope(request['signedProposal']['signature'], request['signedProposal']['proposal_bytes'])
        if self._commit_handler:
            params = {
                'signed_envelope': signed_envelope,
                'request': request['timeout'],
                'timeout': timeout
            }

            return self._commit_handler.commit(params)
        else:
            orderer = self._clientContext.getTargetOrderer(request['orderer'], self.getOrderers(), self._name)
            return orderer.sendBroadcast(signed_envelope, timeout)

    @staticmethod
    def buildEnvelope(clientContext, chaincodeProposal, endorsements, proposalResponse, use_admin_signer):
        header = decode_header(chaincodeProposal.header)

        # TODO review
        chaincodeEndorsedAction = transaction_pb2.ChaincodeEndorsedAction()
        chaincodeEndorsedAction.proposal_response_payload.CopyFrom(proposalResponse.payload)
        chaincodeEndorsedAction.endorsments.CopyFrom(endorsements)

        chaincodeActionPayload = transaction_pb2.ChaincodeActionPayload()
        chaincodeActionPayload.action.CoyFrom(chaincodeEndorsedAction)

        # the TransientMap field inside the original proposal payload is only meant for the
        # endorsers to use from inside the chaincode. This must be taken out before sending
        # to the orderer, otherwise the transaction will be rejected by the validators when
        # it compares the proposal hash calculated by the endorsers and returned in the
        # proposal response, which was calculated without the TransientMap
        originalChaincodeProposalPayload = decode_chaincode_proposal_payload(chaincodeProposal.payload)
        chaincodeProposalPayloadNoTrans = proposal_pb2.ChaincodeProposalPayload()
        chaincodeProposalPayloadNoTrans.input.CopyFrom(originalChaincodeProposalPayload.input)
        chaincodeProposalPayloadNoTrans.chaincode_proposal_payload = chaincodeProposalPayloadNoTrans.SerializeToString()

        transactionAction = transaction_pb2.TransactionAction()
        transactionAction.header.CopyFrom(header.getSignatureHeader())
        transactionAction.payload = chaincodeActionPayload.SerializeToString()

        actions = []
        actions.append(transactionAction)

        transaction = transaction_pb2.Transaction()
        transaction.actions.extend(actions) # TODO review

        payload = common_pb2.Payload()
        payload.header.CopyFrom(header)
        payload.data = transaction.SerializeToString()

        signer = clientContext._getSigningIdentity(use_admin_signer)
        signed_proposal = sign_proposal(signer, payload)
        return create_envelope(signed_proposal.signature, signed_proposal.proposal_bytes)

    async def queryByChaincode(self, request, useAdmin):
        method = 'queryByChaincode'
        _logger.debug(f'{method} - start')

        if not request:
            raise Exception(request, useAdmin)
        if 'txId' in request:
            useAdmin = request['txId'].isAdmin()

        targets = self._getTargets(request['targets'], 'chaincodeQuery')
        signer = self._clientContext._getSigningIdentity(useAdmin)
        tx_id = request['txId'] or TransactionID(signer, useAdmin)
        query_request = {
            'targets': targets,
            'chaincodeId': request['chaincodeId'],
            'fcn': request['fcn'],
            'args': request['args'],
            'transientMap': request['transientMap'],
            'txId': tx_id,
            'signer': signer,
        }

        responses, _ = await Channel.send_transaction_proposal(query_request, self._name, self._clientContext,
                                                               request['request_timeout'])

        _logger.debug(f'{method} - results received')
        results = []
        for pplResponse in responses:
            if pplResponse.response.status != 200:
                if pplResponse.response.message:
                    results.append(Exception(pplResponse.response.message))
                else:
                    results.append(Exception(pplResponse))
            else:
                results.append(pplResponse.response.payload)

        return results

    def verifyProposalResponse(self, proposal_response):
        method = 'verifyProposalResponse'
        _logger.debug(f'{method} - start')

        if not proposal_response:
            raise Exception('Missing proposal response')

        if isinstance(proposal_response, Exception):
            return False

        if not proposal_response.endorsement:
            raise Exception('Parameter must be a ProposalResponse Object')

        endorsement = proposal_response.endorsement

        sid = decode_identity(endorsement.endorser)
        mspid = sid['mspid']
        _logger.debug(f'getMSPbyIdentity - found mspid {mspid}')
        msp = self._msp_manager.getMSP(mspid)

        if not msp:
            raise Exception(f'Failed to locate an MSP instance matching the endorser identity\'s organization {mspid}')
        _logger.debug('verifyProposalResponse - found endorser\'s MSP')

        try:
            identity = msp.deserializeIdentity(endorsement.endorser, False)
            if not identity:
                raise Exception('Unable to find the endorser identity')
        except Exception as e:
            _logger.error(f'verifyProposalResponse -getting endorser identity failed with: {e}')
            return False

        try:
            # see if the identity is trusted
            if not identity.isValid():
                _logger.error('Endorser identity is not valid')
                return False
            _logger.debug('verifyProposalResponse - have a valid identity')

            # check the signature against the endorser and payload hash
            digest = proposal_response.payload + endorsement.endorser
            if not identity.verify(digest, endorsement.signature):
                _logger.error('Proposal signature is not valid')
                return False
        except Exception as e:
            _logger.error(f'verifyProposalResponse - verify failed with: {e}')
            return False

        _logger.debug('verifyProposalResponse - This endorsement has both a valid identity and valid signature')
        return True

    def compareProposalResponseResults(self, proposal_responses):
        method = 'compareProposalResponseResults'
        _logger.debug(f'{method} - start')

        if not isinstance(proposal_responses, list):
            raise Exception(f'proposal_responses must be an array but was {type(proposal_responses)}')

        if len(proposal_responses) == 0:
            raise Exception('proposal_responses is empty')

        if not all([x.status == 200 for x in proposal_responses]):
            return False

        first_one = _getProposalResponseResults(proposal_responses[0])
        i = 1
        while i < len(proposal_responses):
            next_one = _getProposalResponseResults(proposal_responses[i])
            if next_one == first_one: # Verify equality on bytes
                _logger.debug(f'compareProposalResponseResults - read/writes result sets match index={i}')
            else:
                _logger.error(f'compareProposalResponseResults - read/writes result sets do not match index={i}')
                return False

        return True

    def _getTargetForQuery(self, target):
        if isinstance(target, list):
            raise Exception('"target" parameter is an array, but should be a singular peer object or peer name'
                            ' according to the common connection profile loaded by the client instance')

        targets = self._getTargets(target, 'ledgerQuery', True)
        # only want to query one peer
        return [targets[0]]

    def _getFirstAvailableTarget(self, target):
        targets = self._getTargets(target, 'all', True)
        return targets[0]

    def _getTargetForDiscovery(self, target ):
        targets = self._getTargets(target, 'discover', True)
        return targets[0]

    def _getTargets(self, request_targets, role, isTarget=False):
        targets = []

        if request_targets:
            targetsTemp = request_targets
            if not isinstance(request_targets, list):
                targetsTemp = [request_targets]

            for target_peer in targetsTemp:
                if isinstance(target_peer, str):
                    channel_peer = self._channel_peers.get(target_peer)
                    if channel_peer:
                        targets.append(channel_peer.getPeer())
                    else:
                        raise Exception(f'Peer with name "{target_peer}" not assigned to this channel')
                elif target_peer and isinstance(target_peer, Peer):
                    targets.append(target_peer)
                elif target_peer and isinstance(target_peer, ChannelPeer):
                    targets.append(target_peer.peer)
                else:
                    raise Exception('Target peer is not a valid peer object instance')
        else:
            for channel_peer in self._channel_peers:
                if channel_peer.isInRole(role):
                    targets.append(channel_peer.getPeer())

        if len(targets) == 0:
            target_msg = 'targets'
            if isTarget:
                target_msg = 'target'
            if role == 'eventSource':
                target_msg = 'peer'

            raise Exception(f'{target_msg} parameter not specified and no peers are set on this Channel instance or specified for this channel in the network')

        return targets

    def _getOrderer(self, request_orderer):
        if request_orderer:
            if isinstance(request_orderer, str):
                orderer = self._orderers.get(request_orderer)
                if not orderer:
                    raise Exception(f'Orderer {request_orderer} not assigned to the channel')
            elif request_orderer and isinstance(request_orderer, Orderer):
                orderer = request_orderer
            else:
                raise Exception('Orderer is not a valid orderer object instance')
        else:
            orderers = self.getOrderers()
            orderer = orderers[0]
            if not orderer:
                raise Exception('No Orderers assigned to this channel')

        return orderer

    def _buildEndorsementPolicy(self, policy):
        return Policy._build_policy(self.getMSPManager().getMSPSs(), policy) # TODO review parameters place

    def __str__(self):
        orderers = []
        for orderer in self.getOrderers():
            orderers.append(str(orderer))

        peers = []
        for peer in self.getPeers():
            peers.append(str(peer))

        state = {
            'name': self._name,
            'orderers': 'N/A' if len(orderers) <= 0 else orderers,
            'peers': 'N/A' if len(peers) <= 0 else peers
        }

        return json.dumps(state)

    async def _build_handler(self, _handler_path, handler_name):
        method = '_build_handler'
        handler_path = _handler_path
        handler = None

        if not handler_path:
            handler_path = os.environ.get(handler_name) # TODO get from config file
            _logger.debug(f'{method} using path {handler_path} for {handler_name}')
        if handler_path:
            # TODO load module from handler_path
            pass

        return handler


def _getProposalResponseResults(proposal_response):
    if not proposal_response.payload:
        raise Exception('Parameter must be a ProposalResponse Object')

    payload = decode_proposal_response_payload(proposal_response.payload)
    extension = decode_chaincode_action(payload.extension)

    # TODO should we check the status of this action
    _logger.debug(f"_getWriteSet - chaincode action status:{extension['response']['status']} message:{extension['response']['message']}")
    # return a buffer object which has an equals method
    return extension['results'].SerilaizeToString()


class ChannelPeer(object):

    def __init(self, mspid, channel, peer, roles):
        self._mspid = mspid
        if channel and isinstance(channel, Channel):
            if peer and isinstance(peer, Peer):
                self._channel = channel
                self._name = peer.name
                self._peer = peer
                self._roles = {}
                _logger.debug(f'ChannelPeer.const - url: {peer.url}')
                if roles and isinstance(roles, dict):
                    self._roles = roles.copy()  # TODO maybe use deepcopy
            else:
                raise Exception('Missing Peer parameter')
        else:
            raise Exception('Missing Channel parameter')

    def close(self):
        self._peer.close()
        if self._channel_event_hub:
            self._channel_event_hub.close()

    @property
    def mspid(self):
        return self._mspid

    @property
    def name(self):
        return self._name

    @property
    def url(self):
        return self._url

    def setRole(self, role, isIn):
        self._roles[role] = isIn

    def isInRole(self, role):
        if not role:
            raise Exception('Missing "role" parameter')
        elif role in self._roles and self._roles[role] is None:
            return True
        else:
            return self._roles[role]

    def isInOrg(self, mspid):
        if not mspid or not self._mspid:
            return True
        else:
            return mspid == self._mspid

    def getChannelEventHub(self):
        if not self.getChannelEventHub:
            self._channel_event_hub = ChannelEventHub(self._channel, self._peer)

        return self._channel_event_hub

    @property
    def peer(self):
        return self._peer

    def send_proposal(self, proposal, timeout):
        return self._peer.send_proposal(proposal, timeout)

    def send_discovery(self, request, timeout):
        return self._peer.send_discovery(request, timeout)

    def __str__(self):
        return str(self._peer)
