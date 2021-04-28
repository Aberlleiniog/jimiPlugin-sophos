from plugins.sophos.includes import sophos
from core.models import trigger
from core import auth, settings, logging

certSettings = settings.config["sophos"]

class _sophos(trigger._trigger):
    category = list()
    XOrganizationID = str()
    client_id = str()
    client_secret = str()
    tenants = list()
    client_secret_plain = str()
    searchStart = int()
    searchEnd = int()

    def check(self):
        if not self.client_secret_plain:
            self.client_secret_plain = auth.getPasswordFromENC(self.client_secret)
        sophosAPI = sophos.sophos(certSettings["ca"],self.client_id,self.client_secret_plain,self.XOrganizationID)
        for tenant in self.tenants:
            if sophosAPI.setTenant(tenant):
                alerts = sophosAPI.getAlerts(["category={}".format(",".join(self.category))])
                self.result["events"] = {**alerts, "estate" : tenant}

    def setAttribute(self,attr,value):
        if attr == "client_secret" and not value.startswith("ENC "):
            self.client_secret = "ENC {0}".format(auth.getENCFromPassword(value))
            return True
        return super(_sophos, self).setAttribute(attr,value)