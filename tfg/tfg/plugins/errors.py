class PluginError(Exception):
    pass

class PluginNotFound(PluginError):
    pass

class PluginLoadError(PluginError):
    pass
