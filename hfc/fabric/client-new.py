import asyncio
import logging
import json
import re
import os
from _sha256 import sha256

from cryptography.hazmat.primitives import serialization
from yaml import load

from hfc.fabric.package import Package

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from hfc.fabric.baseClient import BaseClient
from hfc.fabric.channel.channel import Channel
from hfc.fabric.msp.identity import SigningIdentity, Signer
from hfc.fabric.orderer import Orderer
from hfc.fabric.peer import Peer
from hfc.fabric.transaction.transaction_id import TransactionID
from hfc.fabric.user import User
from hfc.protos.common import common_pb2, configtx_pb2
from hfc.protos.peer import query_pb2, chaincode_pb2
from hfc.fabric.block_decoder import decode_config_envelope
from hfc.protos.utils import create_envelope
from hfc.util import utils


from hfc.util.utils import proto_b, build_channel_header, build_header, build_proposal, sign_proposal, \
    send_peers_proposal, proto_str, newCryptoSuite, pem_to_der

from ..fabric_ca.caservice import ca_service


consoleHandler = logging.StreamHandler()
_logger = logging.getLogger(__name__)
_logger.setLevel(logging.DEBUG)
_logger.addHandler(consoleHandler)


class Client(BaseClient):
    """
        Main interaction handler with end user.
        Client can maintain several channels.
    """

    def __init__(self):
        super(Client, self).__init__()

        self._clientConfigMspid = None

        self._stateStore = None
        self._userContext = None

        self._network_config = None
        self._msps = {}

        self._devMode = False
        self._adminSigningIdentity = None
        self._tls_mutual = {}

        self._organizations = {}
        self._certificateAuthorities = {}
        self._channels = {}

        self._connection_options = {}

    @staticmethod
    def loadFromConfig(loadConfig):
        client = Client()
        client._loadFromConfig(loadConfig)
        return client

    def _loadFromConfig(self, loadConfig):
        additional_network_config = _getNetworkConfig(loadConfig, self)
        if not self._network_config:
            self._network_config = additional_network_config
        else:
            self._network_config.mergeSettings(additional_network_config)

        if self._network_config.hasClient():
            self._setAdminFromConfig()
            self._setMspidFromConfig()
            self._addConnectionOptionsFromConfig()

    def setTlsClientCertAndKey(self, clientCert=None, clientKey=None):
        _logger.debug('setTlsClientCertAndKey - start')
        if clientCert and clientKey:
            self._tls_mutual['clientCert'] = clientCert
            self._tls_mutual['clientKey'] = clientKey
            self._tls_mutual['clientCertHash'] = None
            self._tls_mutual['selfGenerated'] = False

    def addTlsClientCertAndKey(self, opts): # TODO review modification by reference
        if not self._tls_mutual['selfGenerated'] and self._tls_mutual['clientCert'] and self._tls_mutual['clientKey']:
            opts['clientCert'] = self._tls_mutual['clientCert']
            opts['clientKey'] = self._tls_mutual['clientKey']

            # TODO return opts?

    def buildConnectionOptions(self, options):
        method = 'buildConnectionOptions'
        _logger.debug(f"{method} - start")

        return_options = Client.getConfigSetting('connection-options').copy() # TODO maybe deep copy
        return_options.update(self._connection_options)
        return_options.update(self._getLegacyOptions())
        return_options.update(options)

        if 'clientCert' not in return_options or not return_options['clientCert']:
            self.addTlsClientCertAndKey(return_options)

        return return_options

    def _getLegacyOptions(self):
        MAX_SEND = 'grpc.max_send_message_length'
        MAX_RECEIVE = 'grpc.max_receive_message_length'
        MAX_SEND_V10 = 'grpc-max-send-message-length'
        MAX_RECEIVE_V10 = 'grpc-max-receive-message-length'
        LEGACY_WARN_MESSAGE = 'Setting grpc options by utils.setConfigSetting() is deprecated. Use utils.g(s)etConfigSetting("connection-options")'

        result = {}

        if not Client.getConfigSetting(MAX_RECEIVE):
            result.update({MAX_RECEIVE: Client.getConfigSetting(MAX_RECEIVE)})
        if not Client.getConfigSetting(MAX_RECEIVE_V10):
            result.update({MAX_RECEIVE: Client.getConfigSetting(MAX_RECEIVE_V10)})
        if not Client.getConfigSetting(MAX_SEND):
            result.update({MAX_SEND: Client.getConfigSetting(MAX_SEND)})
        if not Client.getConfigSetting(MAX_SEND_V10):
            result.update({MAX_SEND: Client.getConfigSetting(MAX_SEND_V10)})

        if len(result.keys()) > 0:
            _logger.warning(LEGACY_WARN_MESSAGE)

        return result

    def addConnectionOptions(self, options):
        if options:
            self._connection_options.update(options)

    @property
    def dev_mode(self):
        return self._devMode

    def newChannel(self, name):
        if name in self._channels:
            raise Exception(f'Channel {name} already exists')
        channel = Channel(name, self)
        self._channels[name] = channel
        return channel

    def getChannel(self, name, _raise=True):
        channel = None
        if name:
            channel = self._channels[name]
        elif len(self._channels) > 0:
            channel = list(self._channels.items())[0:1]  # get first one # TODO review

        if channel:
            return channel

        if self._network_config:
            if not name:
                channel_names = self._network_config['_network_config']['channels'].keys()
                name = channel_names[0]

            if name:
                channel = self._network_config.getChannel(name)

        if channel:
            self._channels[name] = channel
            return channel

        errorMessage = f'Channel not found for name {name}'
        if _raise:
            _logger.error(errorMessage)
            raise Exception(errorMessage)
        else:
            _logger.debug(errorMessage)

    def newPeer(self, url, opts):
        return Peer(url, self.buildConnectionOptions(opts))

    def getPeer(self, name):
        peer = None

        if self._network_config:
            peer = self._network_config.getPeer(name)

        if not peer:
            raise Exception(f'Peer with name:{name} not found')

    def getPeersForOrg(self, mspid):
        _mspid = mspid

        if not mspid:
            _mspid = self.getMspid()

        if _mspid and self._network_config:
            organisation = self._network_config.getOrganizationByMspId(_mspid)
            if organisation:
                return organisation.getPeers()

        return []

    def newOrderer(self, url, opts):
        return Orderer(url, self.buildConnectionOptions(opts))

    def getOrderer(self, name):
        orderer = None
        if self._network_config:
            orderer = self._network_config.getOrderer(name)

        if not orderer:
            raise Exception(f'Orderer with name:{name} not found')

        return orderer

    def getPeersForOrgOnChannel(self, channel_names):
        if not isinstance(channel_names, list):
            channel_names = [channel_names]

        peers = []
        temp_peers = {}
        for channel_name in channel_names:
            channel = self.getChannel(channel_name)
            channel_peers = channel.getPeersForOrg()
            for channel_peer in channel_peers:
                temp_peers[channel_peer.name] = channel_peer

        for name in temp_peers:
            peers.append(temp_peers[name])

        return peers

    def getCertificateAuthority(self, name):
        if not self._network_config:
            raise Exception('No common connection profile has been loaded')
        if not self._cryptoSuite:
            raise Exception('A crypto suite has not been assigned to this client')

        ca_info = None

        if name:
            ca_info = self._network_config.getCertificateAuthority(name)
        else:
            client_config = self._network_config.getClientConfig()
            if client_config and client_config['organization']:
                organization_config = self._network_config.getOrganization(client_config['organization'], True)
                ca_infos = organization_config.getCertificateAuthorities()
                if len(ca_infos) > 0:
                    ca_info = ca_infos[0]

        if ca_info:
            ca_service = self._buildCAfromConfig(ca_info)
            ca_info.setFabricCAServices(ca_service)
        else:
            raise Exception('Common connection profile is missing this client\'s organization and certificate authority')

        return ca_info

    def _buildCAfromConfig(self, ca_info):
        tlsCACerts = ca_info.getTlsCACerts()
        if tlsCACerts:
            tlsCACerts = [tlsCACerts]
        else:
            tlsCACerts = []

        connection_options = ca_info.getConnectionOptions()
        verify = True

        if connection_options and isinstance(connection_options['verify'], bool):
            verify = connection_options['verify']

        tls_options = {
            'trustedRoots': tlsCACerts,
            'verify': verify
        }

        ca_url = ca_info.getUrl()
        ca_name = ca_info.getCaName()

        ca_service_class = Client.getConfigSetting('certificate-authority-client') # TODO
        caservice = ca_service(ca_url, tls_options, ca_name, self.cryptoSuite) # TODO review args order

        return caservice

    def getClientConfig(self):
        if not self._network_config and self._network_config.hasClient():
            return self._network_config.getClientConfig()
        return None

    def getMspid(self):
        user = self._userContext
        identity = user.getIdentity()
        mspid = identity.getMSPId()
        if mspid:
            return mspid
        return self._clientConfigMspid

    def newTransactionID(self, admin):
        if admin is not None:
            if isinstance(admin, bool):
                if admin:
                    _logger.debug('newTransactionID - getting an admin TransactionID')
                else:
                    _logger.debug('newTransactionID - getting non admin TransactionID')
            else:
                raise Exception('"admin" parameter must be of type boolean')
        else:
            admin = False
            _logger.debug('newTransactionID - no admin parameter, returning non admin TransactionID')

        return TransactionID(self._getSigningIdentity(admin), admin)

    def extractChannelConfig(self, config_envelope):
        _logger.debug('extractConfigUpdate - start')
        config_envelope = decode_config_envelope(config_envelope)
        return config_envelope['last_update']

    def signChannelConfig(self, loadConfig):
        _logger.debug('signChannelConfigUpdate - start')

        if not loadConfig:
            raise Exception('Channel configuration update parameter is required.')
        if not isinstance(loadConfig, bytes):
            raise Exception('Channel configuration update parameter is not in the correct form.')

        signer = self._getSigningIdentity(True)

        proto_signature_header = common_pb2.SignatureHeader()
        proto_signature_header.creator = signer.identity
        proto_signature_header.nonce = signer.nonce
        signature_header_bytes = proto_signature_header.SerializeToString()

        signing_bytes = signature_header_bytes + loadConfig
        sig = signer.sign(signing_bytes)
        signature_bytes = sig.SerializeToString()

        proto_config_signature = configtx_pb2.ConfigSignature()
        proto_config_signature.signature_header = signature_header_bytes
        proto_config_signature.signature = signature_bytes

        return proto_signature_header

    def createChannel(self, request):
        have_envelope = False
        if 'envelope' in request and request['envelope']:
            have_envelope = True
        return self._create_or_update_channel(request, have_envelope)

    def updateChannel(self, request):
        have_envelope = False
        if 'envelope' in request and request['envelope']:
            have_envelope = True
        return self._create_or_update_channel(request, have_envelope)

    async def _create_or_update_channel(self, request, have_envelope):
        res = []
        async for v in self._create_or_update_channel_request(request, have_envelope):
            res.append(v)
        return res

    def _create_or_update_channel_request(self, request, have_envelope):
        _logger.debug('_create_or_update_channel - start')

        error_msg = None

        if not request:
            raise Exception('Missing all required input request parameters for initialize channel')

        if 'name' not in request:
            error_msg = 'Missing name request parameter'

        if 'txId' not in request:
            error_msg = 'Missing txId request parameter'

        orderer = self.getTargetOrderer(request['orderer'], None, request['name'])


        if have_envelope:
            _logger.debug('_create_or_update_channel - have envelope')
            envelope = common_pb2.Envelope()
            envelope.ParseFromString(request['envelope'])
            signature = envelope.signature
            payload = envelope.payload
        else:
            if 'config' not in request:
                raise Exception('Missing config request parameter containing the configuration of the channel')
            if 'signatures' not in request:
                raise Exception('Missing signatures request parameter for the new channel')
            if not isinstance(request['signatures'], list):
                raise Exception('Signatures request parameter must be an array of signatures')

            _logger.debug('_create_or_update_channel - have config_update')
            proto_config_update_envelope = configtx_pb2.ConfigUpdateEnvelope()
            proto_config_update_envelope.config_update = request['config']

            # convert signatures to protobuf signature
            signatures = request['signatures']
            proto_signatures = utils.string_to_signature(signatures)
            proto_config_update_envelope.signatures.extend(proto_signatures)

            proto_channel_header = utils.build_channel_header(
                common_pb2.HeaderType.Value('CONFIG_UPDATE'),
                request['name'],
                request['txId']['TransactionID']  # TODO maybe we will need to add client_cert_hash
            )

            signer = self._getSigningIdentity(request['txId'].isAdmin())

            proto_header = utils.build_header(signer, proto_channel_header, request['txId']['nonce'])
            proto_payload = common_pb2.Payload()
            proto_payload.header.CopyFrom(proto_header)
            proto_payload.data = proto_config_update_envelope.SerializeToString()
            payload_bytes = proto_payload.SerializeToString()

            sig = signer.sign(payload_bytes)
            signature = sig.SerializeToString()
            payload = payload_bytes

        # assemble the final envelope
        out_envelope = create_envelope(signature, payload)

        _logger.debug('_createOrUpdateChannel - about to send envelope')
        results = []
        async for v in orderer.broadcast(out_envelope):
            results.append(v)
        _logger.debug(f'_createOrUpdateChannel - good results from broadcast :: {results}')
        return results

    async def query_peers(self, request):
        method = 'query_peers'
        _logger.debug(f'{method} - start')

        if not request or 'target' not in request or request['target'] is None:
            raise Exception('Target Peer is required')

        targets = self.getTargetPeers(request['target'])
        if not targets or len(targets) == 0:
            raise Exception('Target Peer not found')

        try:
            discover_request = {
                'target': targets[0],
                'local': True,
                'config': False,
                'useAdmin': request['useAdmin']
            }

            channel = Channel('discover-peers', self)
            discovery_results = await channel._discover(discover_request)
            return discovery_results
        except Exception as e:
            _logger.error(e)
            raise Exception(f'Failed to discover local peers :: {str(e)}')

    async def query_channels(self, peer, useAdmin):
        method = 'query_channels'
        _logger.debug(f'{method} - start')

        if not peer:
            raise Exception('Peer is required')

        targets = self.getTargetPeers(peer)

        signer = self._getSigningIdentity(useAdmin)
        txId = TransactionID(signer, useAdmin)
        request = {
            'targets': targets,
            'chaincodeId': 'cscc',
            'txId': txId,
            'signer': signer,
            'fcn': 'GetChannels',
            'args': []
        }

        responses, _ = Channel.send_transaction_proposal(request, '', self)
        _logger.debug(f'{method} - got response')
        res = await asyncio.gather(*responses)
        if res and isinstance(res, list):
            if len(res) > 1:
                raise Exception('Too many results returned')
            ppl_response = res[0]
            if ppl_response.response:
                _logger.debug(f'{method} - response status :: {ppl_response.response.status}')
                query_trans = query_pb2.ChannelQueryResponse()
                query_trans.ParseFromString(ppl_response.response.payload)
                _logger.debug(f'{method} - ProcessedTransaction.channelInfo.length :: {len(query_trans.channels)}')
                for channel in query_trans.channels:
                    _logger.debug(f'channel id {channel.channel_id}')
                return query_trans
            else:
                raise Exception(ppl_response)

        raise Exception('Payload results are missing from the query')

    async def query_installed_chaincodes(self, peer, useAdmin):
        method = 'query_installed_chaincodes'
        _logger.debug(f'{method} - start')

        if not peer:
            raise Exception('Peer is required')

        targets = self.getTargetPeers(peer)

        signer = self._getSigningIdentity(useAdmin)
        txId = TransactionID(signer, useAdmin)
        request = {
            'targets': targets,
            'chaincodeId': 'lscc',
            'txId': txId,
            'signer': signer,
            'fcn': 'getinstalledchaincodes',
            'args': []
        }

        responses, _ = Channel.send_transaction_proposal(request, '', self)
        _logger.debug(f'{method} - got response')
        res = await asyncio.gather(*responses)
        if res and isinstance(res, list):
            if len(res) > 1:
                raise Exception('Too many results returned')
            ppl_response = res[0]
            if ppl_response.response:
                _logger.debug(f'{method} - response status :: {ppl_response.response.status}')
                query_trans = query_pb2.ChaincodeQueryResponse()
                query_trans.ParseFromString(ppl_response.response.payload)
                _logger.debug(f'{method} - ProcessedTransaction.channelInfo.length :: {len(query_trans.chaincodes)}')
                for chaincode in query_trans.chaincodes:
                    _logger.debug(f'>>> name {chaincode.name}, version {chaincode.version}, path {chaincode.path}')
                return query_trans
            else:
                raise Exception(ppl_response)

        raise Exception('Payload results are missing from the query')

    async def install_chaincode(self, request, timeout):
        if not request:
            raise Exception('Missing input request object on install chaincode request')
        elif 'chaincodePackage' in request:
            _logger.debug('installChaincode - installing chaincode package')
        elif 'chaincodeId' not in request:
            raise Exception('Missing "chaincodeId" parameter in the proposal request')
        elif 'chaincodeVersion' not in request:
            raise Exception('Missing "chaincodeVersion" parameter in the proposal request')
        elif 'chaincodePath' not in request:
            raise Exception('Missing "chaincodePath" parameter in the proposal request')

        peers = self.getTargetPeers(request['targets'])
        if not peers and request['channelNames']:
            peers = self.getPeersForOrgOnChannel(request['channelNames'])

        if peers and len(peers) > 0:
            _logger.debug(f'installChaincode - found peers :: {len(peers)}')
        else:
            raise Exception('Missing peer objects in install chaincode request')

        if 'chaincodePackage' in request and request['chaincodePackage']:
            cdsBytes = request['chaincodePackage']
            _logger.debug(f'installChaincode - using specified chaincode package ({cdsBytes.length} bytes)')
        elif self.dev_mode:
            cdsBytes = None
            _logger.debug('installChaincode - in dev mode, refusing to package chaincode')
        else:
            cdsPkg = Package.fromDirectory({
                'name': request['chaincodeId'],
                'version': request['chaincodeVersion'],
                'path': request['chaincodePath'],
                'type': request['chaincodeType'],
                'metadataPath': request['metadataPath']
            })
            cdsBytes = cdsPkg.SerializeToString()
            _logger.debug(f'installChaincode - built chaincode package ({cdsBytes.length} bytes)')

        # TODO add ESCC/VSCC info here ??????

        lcccSpec = chaincode_pb2.ChaincodeInvocationSpec()
        lcccSpec.chaincode_spec.type = chaincode_pb2.ChaincodeSpec.Type.Value(proto_str(request['chaincodeType']))
        lcccSpec.chaincode_spec.chaincode_id.name = proto_str("lscc")
        lcccSpec.chaincode_spec.input.args.extend([proto_b('install'), cdsBytes])

        tx_id = request['txId']
        if not tx_id:
            signer = self._getSigningIdentity(True)
            tx_id = TransactionID(signer, True)
        else:
            signer = self._getSigningIdentity(tx_id.isAdmin())

        channel_header = build_channel_header(
            common_pb2.HeaderType.Value('ENDORSER_TRANSACTION'),
            '',
            tx_id.transactionID,
            None,
            'lscc',)

        header = build_header(signer, channel_header, request['txId'].nonce)
        proposal = build_proposal(lcccSpec, header)
        signed_proposal = sign_proposal(signer, proposal)

        responses = send_peers_proposal(peers, signed_proposal, timeout)
        res = await asyncio.gather(*responses)
        return res, proposal

    async def initCredentialStores(self):
        if not self._network_config:
            raise Exception('No common connection profile settings found')

        client_config = self._network_config.getClientConfig()
        if client_config and client_config.credentialStore:
            key_value_store = await BaseClient.newDefaultKeyValueStore(client_config.credentialStore)
            self.setStateStore(key_value_store)
            crypto_suite = BaseClient.newCryptoSuite()
            crypto_suite.setCryptoKeyStore(BaseClient.newCryptoKeyStore(client_config.credentialStore.cryptoStore))
            self.setCryptoSuite(crypto_suite)
            return True
        else:
            raise Exception('No credentialStore settings found')

    def setStateStore(self, keyValueStore):
        self._stateStore = keyValueStore
        # userContext invalid on state store change, set to null
        self._userContext = None

    def _getSigningIdentity(self, admin):
        _logger.debug(f'_getSigningIdentity - admin parameter is {type(admin)} :{admin}')
        if admin and self._adminSigningIdentity:
            return self._adminSigningIdentity
        else:
            if self._userContext:
                return self._userContext.getSigningIdentity()
            else:
                raise Exception('No identity has been assigned to this client')

    def setAdminSigningIdentity(self, private_key, certificate, mspid):
        _logger.debug(f'setAdminSigningIdentity - start mspid:{mspid}')
        if private_key is None or private_key == '':
            raise Exception('Invalid parameter. Must have a valid private key.')
        if certificate is None or certificate == '':
            raise Exception('Invalid parameter. Must have a valid certificate.')
        if mspid is None or mspid == '':
            raise Exception('Invalid parameter. Must have a valid mspid.')

        crypto_suite = self.getCryptoSuite()
        if not crypto_suite:
            crypto_suite = BaseClient.newCryptoSuite()

        key = crypto_suite.importKey(private_key, {'ephemeral': True})
        public_key = crypto_suite.importKey(certificate, {'ephemeral': True})

        self._adminSigningIdentity = SigningIdentity(certificate, public_key, mspid, crypto_suite, Signer(crypto_suite, key))

    def _setAdminFromConfig(self):
        admin_key = None
        admin_cert = None
        mspid = None

        if not self._network_config:
            raise Exception('No common connection profile has been loaded')

        client_config = self._network_config.getClientConfig()
        if client_config and 'organization' in client_config and client_config['organization']:
            organization_config = self._network_config.getOrganization(client_config['organization'], True)
            if organization_config:
                mspid = organization_config.mspid
                admin_key = organization_config.admin_private_key
                admin_cert = organization_config.admin_Cert

            if admin_key and admin_cert and mspid:
                self.setAdminSigningIdentity(admin_key, admin_cert, mspid)

    def _setMspidFromConfig(self):
        if not self._network_config:
            raise Exception('No common connection profile has been loaded')

        client_config = self._network_config.getClientConfig()
        if client_config and 'organization' in client_config and client_config['organization']:
            organization_config = self._network_config.getOrganization(client_config['organization'], True)
            if organization_config:
                self._clientConfigMspid = organization_config.mspid

    def _addConnectionOptionsFromConfig(self):
        if not self._network_config:
            raise Exception('No common connection profile has been loaded')

        client_config = self._network_config.getClientConfig()
        if client_config \
                and 'organization' in client_config \
                and client_config['organization'] \
                and 'options' in client_config['organization'] \
                and client_config['connection']['options']:
            self.addConnectionOptions(client_config['connection']['options'])

    async def _setUserFromConfig(self, opts):

        if opts is None:
            opts = {}

        if not 'username' in opts:
            raise Exception('Missing parameter. Must have a username.')
        if not self._network_config or not self._stateStore or not self._cryptoSuite:
            raise Exception('Client requires a common connection profile loaded, stores attached, and crypto suite.')

        self._userContext = None

        user = await self.getUserContext(opts['username'], True)
        if user and user.is_enrolled():
            _logger.debug('Successfully loaded member from persistence')
            return user

        if 'password' in opts:
            raise Exception('Missing parameter. Must have a password.')

        mspid = None
        client_config = self._network_config.getClientConfig()
        if client_config and 'organization' in client_config and client_config['organization']:
            organization_config = self._network_config.getOrganization(client_config['organization'], True)
            if organization_config:
                mspid = organization_config.mspid

        if not mspid:
            raise Exception('Common connection profile is missing this client\'s organization and mspid')

        ca_service = self.getCertificateAuthority(opts['caName'])

        enrollment = await ca_service.enroll({
            'enrollmentID': opts['username'],
            'enrollmentSecret': opts['password']
        })
        _logger.debug(f'Successfully enrolled user "{opts.username}')

        cryptoContent = {'signedCertPEM': enrollment['certificate']}
        keyBytes = None
        try:
            # TODO review (maybe its enrollment._private_key)
            keyBytes = enrollment['key'].private_bytes(encoding=serialization.Encoding.PEM,
                                                       format=serialization.PrivateFormat.PKCS8,
                                                       encryption_algorithm=serialization.NoEncryption())
        except:
            _logger.debug('Cannot access enrollment private key bytes')

        if keyBytes is not None and keyBytes.startswith('-----BEGIN'):
            cryptoContent['privateKeyPEM'] = keyBytes
        else:
            cryptoContent['privateKeyPEM'] = enrollment['key']

        return self.createUser({
            'username': opts['username'],
            'mspid': mspid,
            'cryptoContent': cryptoContent
        })

    async def saveUserToStateStore(self):
        _logger.debug(f'saveUserToStateStore, userContext: {self._userContext}')

        if not self._userContext:
            _logger.debug('saveUserToStateStore Promise rejected, Cannot save user to state store when userContext is null.')
            raise Exception('Cannot save user to state store when userContext is null.')
        if not self._userContext._name:
            _logger.debug('saveUserToStateStore Promise rejected, Cannot save user to state store when userContext has no name.')
            raise Exception('Cannot save user to state store when userContext has no name.')
        if not self._stateStore:
            _logger.debug('saveUserToStateStore Promise rejected, Cannot save user to state store when stateStore is null.')
            raise Exception('Cannot save user to state store when stateStore is null.')

        _logger.debug('saveUserToStateStore, begin promise stateStore.setValue')
        result = await self._stateStore.setValue(self._userContext._name, self._userContext, str(self._userContext)) # TODO review
        _logger.debug(f'saveUserToStateStore, store.setValue, result = {result}')
        return self._userContext

    async def setUserContext(self, user, skipPersistence):
        _logger.debug(f'setUserContext - user: ${user}, skipPersistence: {skipPersistence}')
        if not user:
            _logger.debug('setUserContext, Cannot save null userContext.')
            raise Exception('Cannot save null userContext.')

        if user and isinstance(user, User):
            self._userContext = user
            if not skipPersistence:
                _logger.debug('setUserContext - begin promise to saveUserToStateStore')
                return self.saveUserToStateStore()
            _logger.debug('setUserContext - resolved user')
            return user

        # must be they have passed in an object
        _logger.debug('setUserContext - will try to use common connection profile to set the user')
        return self._setUserFromConfig(user)

    async def getUserContext(self, name, checkPersistence):
        if isinstance(name, bool) and checkPersistence is not None:
            raise Exception('Illegal arguments: "checkPersistence" is truthy but "name" is undefined')

        if isinstance(checkPersistence, bool) and checkPersistence and (not isinstance(name, str) or name is None):
            raise Exception('Illegal arguments: "checkPersistence" is truthy but "name" is not a valid string value')

        username = name
        if (self._userContext and name and self._userContext.getName() == name) or (self._userContext and not name):
            return self._userContext
        else:
            if not username:
                return None

            # first check if there is a user context of the specified name in persistence
            if isinstance(checkPersistence, bool) and checkPersistence:
                if not self._stateStore:
                    return None  # we don't have it in memory or persistence, just return null
                userContext = await self.loadUserFromStateStore(username)

                if userContext:
                    _logger.debug(f'Requested user "{name}" loaded successfully from the state store on this Client instance')
                    return self.setUserContext(userContext, True)
                else:
                    _logger.debug(f'Requested user "{name}" not loaded from the state store on this Client instance')
                    return None
            else:
                return None

    async def loadUserFromStateStore(self, name):
        memberStr = await self._stateStore.getValue(name)
        if not memberStr:
            _logger.debug(f'Failed to find "{name}" in local key value store')
            return None

        newUser = User(name)
        if not self.getCryptoSuite():
            _logger.debug('loadUserFromStateStore, cryptoSuite is not set, will load using defaults')

        newUser.setCryptoSuite(self.getCryptoSuite())
        data = await newUser.fromString(memberStr, True) # TODO rework
        if not data:
            _logger.debug(f'Failed to load user "{name}" from local key value store')
            return None
        _logger.debug(f'Successfully load user "{name}" from local key value store')
        return data

    def getStateStore(self):
        return self._stateStore

    async def createUser(self, opts):
        _logger.debug(f'opts = {opts}')

        if not opts:
            raise Exception('Client.createUser missing required \'opts\' parameter.')
        if 'username' not in opts or len(opts['username']) < 1:
            raise Exception('Client.createUser parameter \'opts username\' is required.')
        if 'mspid' not in opts or len(opts['mspid']) < 1:
            raise Exception('Client.createUser parameter \'opts mspid\' is required.')

        if 'cryptoContent' in opts and opts['cryptoContent']:
            if 'privateKey' not in opts['cryptoContent'] and 'privateKeyPEM' not in opts['cryptoContent'] and 'privateKeyObj' not in opts['cryptoContent']:
                raise Exception('Client.createUser one of \'opts cryptoContent privateKey, privateKeyPEM or privateKeyObj\' is required.')
            if 'signedCert' not in opts['cryptoContent'] and 'signedCertPEM' not in opts['cryptoContent']:
                raise Exception('Client.createUser either \'opts cryptoContent signedCert or signedCertPEM\' is required.')
        else:
            raise Exception('Client.createUser parameter \'opts cryptoContent\' is required.')

        if self.getCryptoSuite() is None:
            _logger.debug('cryptoSuite is None, creating default cryptoSuite and cryptoKeyStore')
            self.setCryptoSuite(newCryptoSuite())
            self.getCryptoSuite().setCryptoKeyStore(Client.newCryptoKeyStore()) # This is impossible
        else:
            if self.getCryptoSuite()._cryptoKeyStore:
                _logger.debug('cryptoSuite has a cryptoKeyStore')
            else:
                _logger.debug('cryptoSuite does not have a cryptoKeyStore')

        user = User(opts['username'])
        privateKeyPEM = opts['cryptoContent']['privateKeyPEM']
        if opts['cryptoContent']['privateKey']:
            with open(opts['cryptoContent']['privateKey'], 'r') as f: # TODO review
                privateKeyPEM = f.read()

        if privateKeyPEM:
            _logger.debug('then privateKeyPEM data')
            if opts['skipPersistence']:
                importedKey = await self.getCryptoSuite().importKey(privateKeyPEM,  {'ephemeral': True}) # TODO review
            else:
                importedKey = await self.getCryptoSuite().importKey(privateKeyPEM,
                                                                    {'ephemeral': not self.getCryptoSuite()._cryptoKeyStore})  # TODO review
        else:
            importedKey = opts['cryptoContent']['privateKeyObj']

        signedCertPEM = opts['cryptoContent']['signedCertPEM']
        if opts['cryptoContent']['signedCertPEM']:
            with open(opts['cryptoContent']['signedCert'], 'r') as f:  # TODO review
                signedCertPEM = f.read()

        _logger.debug('then signedCertPEM data')
        user.setCryptoSuite(self.getCryptoSuite())
        await user.setEnrollment(importedKey, signedCertPEM.toString(), opts['mspid'], opts['skipPersistence']) # TODO review
        _logger.debug('then setUserContext')
        await self.setUserContext(user, opts['skipPersistence'])
        _logger.debug('then user')
        return user

    def getTargetPeers(self, request_targets):
        method = 'getTargetPeers'
        _logger.debug(f'{method} - start')

        targets = []
        targetsTemp = request_targets
        if request_targets:
            if isinstance(request_targets, list):
                targetsTemp = [request_targets]
            for target_peer in targetsTemp:
                if isinstance(target_peer, str):
                    targets.append(self.getPeer(target_peer))
                elif target_peer and isinstance(target_peer, Peer):
                    targets.append(target_peer)
                else:
                    raise Exception('Target peer is not a valid peer object instance')

        if len(targets) > 0:
            return targets
        else:
            return None

    def getTargetOrderer(self, request_orderer=None, channel_orderers=None, channel_name=None):
        method = 'getTargetOrderer'
        _logger.debug(f'{method} - start')

        if request_orderer:
            if isinstance(request_orderer, str):
                orderer = self.getOrderer(request_orderer)
            elif request_orderer and isinstance(request_orderer, Orderer):
                orderer = request_orderer
            else:
                raise Exception('"orderer" request parameter is not valid. Must be an orderer name or "Orderer" object.')
        elif channel_orderers and isinstance(channel_orderers, list) and len(channel_orderers) > 0:
            orderer = channel_orderers[0]
        elif channel_name and self._network_config:
            temp_channel = self.getChannel(channel_name, False)
            if temp_channel:
                temp_orderers = temp_channel.getOrderers()
                if temp_orderers and len(temp_orderers) > 0:
                    orderer = temp_orderers[0]
                else:
                    raise Exception('"orderer" request parameter is missing and there are no orderers defined on this'
                                    ' channel in the common connection profile')
            else:
                raise Exception(f'Channel name {channel_name} was not found in the common connection profile')
        else:
            raise Exception('Missing "orderer" request parameter')

        return orderer

    def getClientCertHash(self, create):
        method = 'getClientCertHash'
        _logger.debug(f'{method} - start')

        if 'clientCertHash' in self._tls_mutual and self._tls_mutual['clientCertHash']:
            return self._tls_mutual['clientCertHash']

        if 'clientCert' not in self._tls_mutual and not self._tls_mutual['clientCert'] and create:
            self.setTlsClientCertAndKey()

        if 'clientCert' in self._tls_mutual and self._tls_mutual['clientCert']:
            _logger.debug(f"{method} - using clientCert {self._tls_mutual['clienCert']}")

            b64der = pem_to_der(self._tls_mutual['clientCert'])
            self._tls_mutual['clientCertHash'] = sha256(b64der).digest() # TODO work with different hash
        else:
            _logger.debug(f'{method} no tls client cert')

        return self._tls_mutual['clientCertHash']


def _getNetworkConfig(loadConfig, client):
    method = '_getNetworkConfig'

    if isinstance(loadConfig, str):
        network_config_loc = os.path.abspath(loadConfig)
        _logger.debug(f'{method} - looking at absolute path of ==>{network_config_loc}<==')
        with open(network_config_loc, 'r') as f:
            file_data = f.read()
        _, file_ext = os.path.splitext(network_config_loc)

        pattern = re.compile('/(yml|yaml)$/i')  # TODO verify
        if pattern.match(file_ext):
            network_data = load(file_data, Loader=Loader)
        else:
            network_data = json.loads(file_data)
    else:
        network_data = loadConfig

    try:
        if not network_data:
            raise Exception('missing configuration data')
        if 'version' not in network_data:
            raise Exception('"version" is missing')

        parsing = Client.getConfigSetting('network-config-schema')
        if not parsing:
            raise Exception('missing "network-config-schema" configuration setting')

        pieces = network_data['version'].split('.')
        version = pieces[0] + '.' + pieces[1]
        if not parsing[version]:
            raise Exception('common connection profile has an unknown "version"')

        # TODO
        # network_config = NetworkConfig(network_data, client, network_config_loc)
    except Exception as e:
        raise Exception(f'Invalid common connection profile due to {str(e)}')

    # return network_config

