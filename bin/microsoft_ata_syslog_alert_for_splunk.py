
# encoding = utf-8
# Always put this line at the beginning of this file
import ta_microsoft_ata_syslog_alert_for_splunk_declare

import os
import sys

from alert_actions_base import ModularAlertBase
import modalert_microsoft_ata_syslog_alert_for_splunk_helper

class AlertActionWorkermicrosoft_ata_syslog_alert_for_splunk(ModularAlertBase):

    def __init__(self, ta_name, alert_name):
        super(AlertActionWorkermicrosoft_ata_syslog_alert_for_splunk, self).__init__(ta_name, alert_name)

    def validate_params(self):
        return True

    def process_event(self, *args, **kwargs):
        status = 0
        try:
            if not self.validate_params():
                return 3
            status = modalert_microsoft_ata_syslog_alert_for_splunk_helper.process_event(self, *args, **kwargs)
        except (AttributeError, TypeError) as ae:
            self.log_error("Error: {}. Please double check spelling and also verify that a compatible version of Splunk_SA_CIM is installed.".format(ae.message))
            return 4
        except Exception as e:
            msg = "Unexpected error: {}."
            if e.message:
                self.log_error(msg.format(e.message))
            else:
                import traceback
                self.log_error(msg.format(traceback.format_exc()))
            return 5
        return status

if __name__ == "__main__":
    exitcode = AlertActionWorkermicrosoft_ata_syslog_alert_for_splunk("TA_microsoft-ata-syslog-alert-for-splunk", "microsoft_ata_syslog_alert_for_splunk").run(sys.argv)
    sys.exit(exitcode)
