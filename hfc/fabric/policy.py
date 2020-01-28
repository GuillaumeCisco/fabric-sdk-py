import logging

from hfc.protos.common import policies_pb2
from hfc.protos.msp import msp_principal_pb2
from hfc.util.utils import proto_b

_logger = logging.getLogger(__name__)
_logger.setLevel(logging.DEBUG)

#TODO rework

class Policy(object):

    def _build_principal(self, identity):
        if 'role' not in identity:
            raise Exception('NOT IMPLEMENTED')

        newPrincipal = msp_principal_pb2.MSPPrincipal()

        newPrincipal.principal_classification = \
            msp_principal_pb2.MSPPrincipal.ROLE

        newRole = msp_principal_pb2.MSPRole()

        roleName = identity['role']['name']
        if roleName == 'peer':
            newRole.role = msp_principal_pb2.MSPRole.PEER
        elif roleName == 'member':
            newRole.role = msp_principal_pb2.MSPRole.MEMBER
        elif roleName == 'admin':
            newRole.role = msp_principal_pb2.MSPRole.ADMIN
        else:
            raise Exception(f'Invalid role name found: must'
                            f' be one of "peer", "member" or'
                            f' "admin", but found "{roleName}"')

        mspid = identity['role']['mspId']
        if not mspid or not isinstance(mspid, str):
            raise Exception(f'Invalid mspid found: "{mspid}"')
        newRole.msp_identifier = mspid.encode()

        newPrincipal.principal = newRole.SerializeToString()

        return newPrincipal

    def _get_policy(self, policy):
        type = list(policy.keys())[0]
        # signed-by case
        if type == 'signed-by':
            signedBy = policies_pb2.SignaturePolicy()
            signedBy.signed_by = policy['signed-by']
            return signedBy
        # n-of case
        else:
            n = int(type.split('-of')[0])

            nOutOf = policies_pb2.SignaturePolicy.NOutOf()
            nOutOf.n = n
            subs = []
            for sub in policy[type]:
                subPolicy = self._get_policy(sub)
                subs.append(subPolicy)

            nOutOf.rules.extend(subs)

            nOf = policies_pb2.SignaturePolicy()
            nOf.n_out_of.CopyFrom(nOutOf)

            return nOf

    def _check_policy(self, policy):
        if not policy:
            raise Exception('Missing Required Param "policy"')

        if 'identities' not in policy \
                or policy['identities'] == '' \
                or not len(policy['identities']):
            raise Exception('Invalid policy, missing'
                            ' the "identities" property')
        elif not isinstance(policy['identities'], list):
            raise Exception('Invalid policy, the "identities"'
                            ' property must be an array')

        if 'policy' not in policy \
                or policy['policy'] == '' \
                or not len(policy['policy']):
            raise Exception('Invalid policy, missing the'
                            ' "policy" property')

    @staticmethod
    def _build_policy(self, policy, msps=None, returnProto=False):
        proto_signature_policy_envelope = \
            policies_pb2.SignaturePolicyEnvelope()

        if policy:
            self._check_policy(policy)
            proto_signature_policy_envelope.version = 0
            proto_signature_policy_envelope.rule.CopyFrom(
                self._get_policy(policy['policy']))
            proto_signature_policy_envelope.identities.extend(
                [self._build_principal(x) for x in policy['identities']])
        else:
            # TODO need to support MSPManager
            # no policy was passed in, construct a 'Signed By any member
            # of an organization by mspid' policy
            # construct a list of msp principals to select from using the
            # 'n out of' operator

            # for not making it fail with current code
            return proto_b('')

            principals = []
            signedBys = []
            index = 0

            if msps is None:
                msps = []

            for msp in msps:
                onePrn = msp_principal_pb2.MSPPrincipal()
                onePrn.principal_classification = \
                    msp_principal_pb2.MSPPrincipal.ROLE

                memberRole = msp_principal_pb2.MSPRole()
                memberRole.role = msp_principal_pb2.MSPRole.MEMBER
                memberRole.msp_identifier = msp

                onePrn.principal = memberRole.SerializeToString()

                principals.append(onePrn)

                signedBy = policies_pb2.SignaturePolicy()
                index += 1
                signedBy.signed_by = index
                signedBys.append(signedBy)

            if len(principals) == 0:
                raise Exception('Verifying MSPs not found in the'
                                ' channel object, make sure'
                                ' "initialize()" is called first.')

            oneOfAny = policies_pb2.SignaturePolicy.NOutOf()
            oneOfAny.n = 1
            oneOfAny.rules.extend(signedBys)

            noutof = policies_pb2.SignaturePolicy()
            noutof.n_out_of.CopyFrom(oneOfAny)

            proto_signature_policy_envelope.version = 0
            proto_signature_policy_envelope.rule.CopyFrom(noutof)
            proto_signature_policy_envelope.identities.extend(principals)

        if returnProto:
            return proto_signature_policy_envelope

        return proto_signature_policy_envelope.SerializeToString()
