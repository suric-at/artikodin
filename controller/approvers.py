import logging
from datetime import datetime


def clean_approvers(approvers):
    valid_approvers = []
    for approver in approvers:
        if isinstance(approver, Approver):
            valid_approvers.append(approver)
            continue

        try:
            valid_approvers.append(Approver(approver))
        except RuntimeError as e:
            logging.warning(e)
    return valid_approvers


class Approver(object):
    def __init__(self, yaml_data):
        if isinstance(yaml_data, str):
            yaml_data = {'handle': yaml_data}
        elif not isinstance(yaml_data, dict):
            raise RuntimeError("Invalid approver: {}".format(yaml_data))
        elif 'handle' not in yaml_data:
            raise RuntimeError("Invalid approver: {}".format(yaml_data))

        self.logger = logging.getLogger(__name__)

        self._handle = yaml_data['handle']
        self._reviewer = yaml_data.get('reviewer', False)

        self._from = None
        if 'from' in yaml_data:
            if not isinstance(yaml_data['from'], datetime):
                self.logger.warning("Approver 'from' parameter is not a datetime object")
            elif not yaml_data['from'].tzinfo:
                self.logger.warning("Approver 'from' parameter does not have timezone information")
            else:
                self._from = yaml_data['from']

        self._to = None
        if 'to' in yaml_data:
            if not isinstance(yaml_data['to'], datetime):
                self.logger.warning("Approver 'to' parameter is not a datetime object")
            elif not yaml_data['to'].tzinfo:
                self.logger.warning("Approver 'to' parameter does not have timezone information")
            else:
                self._to = yaml_data['to']

    @property
    def handle(self):
        return self._handle

    @property
    def from_date(self):
        return self._from

    @property
    def to_date(self):
        return self._to

    @property
    def reviewer(self):
        return self._reviewer

    def applies_to(self, date):
        return ((self._from is None or self._from <= date) and
                (self._to is None or self._to > date))

    def __repr__(self):
        return "<Approver handle={} reviewer={} from={} to={}>".format(
            self._handle,
            self._reviewer,
            self._from,
            self._to
        )
