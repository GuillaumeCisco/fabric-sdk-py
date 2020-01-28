import logging

from hfc.fabric.user import User

_logger = logging.getLogger(__name__)
_logger.setLevel(logging.DEBUG)


class TransactionID(object):

    def __init__(self, signer_or_userContext, admin=False):
        _logger.debug('constructor - start')

        if not signer_or_userContext:
            raise Exception('Missing userContext or signing identity parameter')

        if isinstance(signer_or_userContext, User):
            signer = signer_or_userContext.getSigningIdentity()
        else:
            signer = signer_or_userContext

        self._nonce = crypto.generate_nonce(24)
        creator_bytes = signer.SerializeToString()
        trans_bytes = self._nonce + creator_bytes
        trans_hash = crypto.hash(trans_bytes)
        self._transaction_id = trans_hash.hexdigest()
        _logger.debug(f'const - transaction_id {self._transaction_id }')

        self._admin = admin

    @property
    def transactionID(self):
        return self._transaction_id

    @property
    def nonce(self):
        return self._nonce

    def isAdmin(self):
        if self._admin:
            return True
        else:
            return False
