
# encoding = utf-8
# Always put this line at the beginning of this file
import ta_thehive_ce_declare

import sys
# sys.path.insert(0, os.path.join(os.path.dirname(__file__), "packages",))

from alert_actions_base import ModularAlertBase
import modalert_thehive_ce_alert_helper


class AlertActionWorkerthehive_ce_alert(ModularAlertBase):

    def __init__(self, ta_name, alert_name):
        super(AlertActionWorkerthehive_ce_alert, self).__init__(
            ta_name,
            alert_name
        )

    def validate_params(self):

        if not self.get_param("th_instance"):
            self.log_error(
                'th_instance is a mandatory parameter, but its value is None.'
            )
            return False

        if not self.get_param("th_severity"):
            self.log_error(
                'th_severity is a mandatory parameter, but its value is None.'
            )
            return False

        if not self.get_param("th_tlp"):
            self.log_error(
                'th_tlp is a mandatory parameter, but its value is None.'
            )
            return False

        if not self.get_param("th_pap"):
            self.log_error(
                'th_pap is a mandatory parameter, but its value is None.'
            )
            return False
        return True

    def process_event(self, *args, **kwargs):
        status = 0
        try:
            if not self.validate_params():
                return 3
            status = modalert_thehive_ce_alert_helper.process_event(
                self, *args, **kwargs
            )
        except (AttributeError, TypeError) as ae:
            if ae.message:
                self.log_error(
                    "Error: {}. Please double check spelling and also verify \
that a compatible version of Splunk_SA_CIM is installed.".format(ae.message)
                )
            else:
                msg = "Unexpected error: {}."
                import traceback
                self.log_error(msg.format(traceback.format_exc()))
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
    exitcode = AlertActionWorkerthehive_ce_alert(
        "TA_thehive_ce",
        "thehive_ce_alert"
    ).run(sys.argv)
    sys.exit(exitcode)
