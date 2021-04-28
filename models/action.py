from plugins.sophos.includes import sophos
from core.models import action
from core import auth, settings, logging, helpers

certSettings = settings.config["sophos"]

class _sophosEndpoint(action._action):
    endpointID = str()
    XOrganizationID = str()
    client_id = str()
    client_secret = str()
    tenant = str()
    client_secret_plain = str()

    def run(self,data,persistentData,actionResult):
        endpointID = helpers.evalString(self.endpointID,{"data" : data})
        tenant = helpers.evalString(self.tenant,{"data" : data})
        if not self.client_secret_plain:
            self.client_secret_plain = auth.getPasswordFromENC(self.client_secret)


            if len(endpoint) > 0:
                actionResult["data"] = endpoint[0]
                actionResult["result"] = True
                actionResult["rc"] = 0

    def setAttribute(self,attr,value):
        if attr == "client_secret" and not value.startswith("ENC "):
            self.client_secret = "ENC {0}".format(auth.getENCFromPassword(value))
            return True
        return super(_sophosEndpoint, self).setAttribute(attr,value)