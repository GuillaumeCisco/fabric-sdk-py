import logging

_logger = logging.getLogger(__name__)


# config is a singleton object
class Config(object):

    class __Config:
        def __init(self):
            self._fileStores = []
            self._config = {}

    instance = None

    def __init__(self):

        if not Config.instance:
            Config.instance = Config.__Config()

    def __getattr(self, name):
        return getattr(self.instance, name)

    # TODO should we implement mapSettings (see default file)

    def reorderFileStores(self, path, bottom=None):
        for fileStore in self.instance._fileStores:
            del self.instance._config[fileStore]

        if bottom is not None:
            self.instance._fileStores.append(path)
        else:
            self.instance._fileStores.insert(0, path)

        for fileStore in self.instance._fileStores:
            self.instance._config[fileStore] = fileStore  # TODO review

    def file(self, path):
        if not isinstance(path, str):
            raise Exception('The "path" parameter must be a string')

        self.reorderFileStores(path)

    def get(self, name, default_value):
        return self.instance._config.get(name, default_value)

    def set(self, name, value):
        self.instance._config[name] = value
