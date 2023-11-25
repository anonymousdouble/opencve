from opencve.checks import BaseCheck
from opencve.commands.utils import CveUtil
from opencve.extensions import db


class Cvss(BaseCheck):
    def execute(self):

        old_metrics = self.cve_obj.json.get("metrics")
        new_metrics = self.cve_json.get("metrics")

        # Check the new CVSS scores
        new = {}
        if "cvssMetricV30" in new_metrics:
            new["v30"] = new_metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

        if "cvssMetricV2" in new_metrics:
            new["v2"] = new_metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        # Retrieve the old CVSS scores
        old = {}
        if "cvssMetricV30" in old_metrics:
            old["v30"] = old_metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

        if "cvssMetricV2" in old_metrics:
            old["v2"] = old_metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        # Update the CVE
        if old != new:
            self.cve_obj.cvss2 = new.get("v2")
            self.cve_obj.cvss3 = new.get("v30")
            db.session.commit()

            # Create the event with the CVSS changes
            event = CveUtil.create_event(
                self.cve_obj, self.cve_json, "cvss", {"old": old, "new": new}
            )
            return event

        return None
