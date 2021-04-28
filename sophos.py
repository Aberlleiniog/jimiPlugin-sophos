from core import plugin, model

class _sophos(plugin._plugin):
    version = 0.2

    def install(self):
        # Register models
        model.registerModel("sophos","_sophos","_trigger","plugins.sophos.models.trigger")
        model.registerModel("sophosEndpoint","_sophosEndpoint","_action","plugins.sophos.models.action")
        model.registerModel("assetSophos","_assetSophos","_action","plugins.sophos.models.assetSophos")
        return True

    def uninstall(self):
        # deregister models
        model.deregisterModel("sophos","_sophos","_trigger","plugins.sophos.models.trigger")
        model.deregisterModel("sophosEndpoint","_sophosEndpoint","_action","plugins.sophos.models.action")
        model.deregisterModel("assetSophos","_assetSophos","_action","plugins.sophos.models.assetSophos")
        return True

    def upgrade(self,LatestPluginVersion):
        if self.version < 0.2:
            model.registerModel("sophosEndpoint","_sophosEndpoint","_action","plugins.sophos.models.action")
        return True
    