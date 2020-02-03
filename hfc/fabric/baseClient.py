from hfc.util.crypto.crypto import ecies
from hfc.util.keyvaluestore import FileKeyValueStore
from hfc.util.utils import getConfigSetting, setConfigSetting


class BaseClient(object):

    def __init__(self):
        self._cryptoSuite = None

    @staticmethod
    def newCryptoSuite(setting=None):
        return ecies() # TODO review

    @staticmethod
    def newCryptoKeyStore(KVSImplClass, opts=None):
        raise Exception('Not yet implemented')  # TODO rework

    @staticmethod
    def newDefaultKeyValueStore(options):
        return FileKeyValueStore(options['path'])  # TODO rework

    @staticmethod
    def setLogger(logger):
        err = ''

        if not hasattr(logger['debug'], '__call__'):
            err += 'debug() '
        if not hasattr(logger['info'], '__call__'):
            err += 'info() '
        if not hasattr(logger['warn'], '__call__'):
            err += 'warn() '
        if not hasattr(logger['error'], '__call__'):
            err += 'error() '

        if not err:
            raise Exception(f'The "logger" parameter must be an object that implements the following methods, which are missing: {err}')

        # TODO how to set logger globally

    # @staticmethod
    # def getLogger(name):
    #     return getLogger(name) # TODO

    @staticmethod
    def getConfigSetting(name, default_value=None):
        return getConfigSetting(name, default_value)

    @staticmethod
    def setConfigSetting(name, value):
        return setConfigSetting(name, value)  # TODO

    # @staticmethod
    # def addConfigFile(path):
    #     addConfigFile(path)  # TODO

    def setCryptoSuite(self, cryptoSuite):
        self._cryptoSuite = cryptoSuite

    def getCryptoSuite(self):
        return self._cryptoSuite

    # @staticmethod
    # def normalizeX509(raw):
    #     normalizeX509(raw)  # TODO
