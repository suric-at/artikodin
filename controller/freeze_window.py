import hashlib
import json
import logging
import re
from datetime import datetime

from approvers import clean_approvers
from utils import force_list
from repository_list import RepositoryList


class FreezeWindow(object):
    def __init__(self, yaml_data, default_org=None):
        # Skip if there is no from or no to
        if 'from' not in yaml_data or 'to' not in yaml_data:
            raise RuntimeError("window definition does not have 'from' or 'to'")

        # Check that 'from' and 'to' have been loaded properly as datetime objects
        # with timezone information; error out if object is str or any other type than
        # datetime
        if not isinstance(yaml_data['from'], datetime):
            raise RuntimeError("window definition parameter 'from' is not a datetime object")
        if not isinstance(yaml_data['to'], datetime):
            raise RuntimeError("window definition parameter 'to' is not a datetime object")
        if not yaml_data['from'].tzinfo:
            raise RuntimeError("window definition parameter 'from' does not have timezone information")
        if not yaml_data['to'].tzinfo:
            raise RuntimeError("window definition parameter 'to' does not have timezone information")
        if yaml_data['from'] >= yaml_data['to']:
            raise RuntimeError("window definition parameter 'from' is not before 'to'")

        self.logger = logging.getLogger('freeze-window')

        self._reason = yaml_data.get('reason')
        self._from = yaml_data['from']
        self._to = yaml_data['to']

        self._approvers = clean_approvers(force_list(yaml_data.get('approvers')))

        # Cleanup invalid repositories from the lists
        self._repo_only = yaml_data['only'] = \
            RepositoryList(yaml_data.get('only'), default_org)
        self._repo_include = yaml_data['include'] = \
            RepositoryList(yaml_data.get('include'), default_org)
        self._repo_exclude = yaml_data['exclude'] = \
            RepositoryList(yaml_data.get('exclude'), default_org)

        # Add window id
        if 'id' in yaml_data and not isinstance(yaml_data['id'], str):
            self.logger.warning('Freeze window %s has an invalid id; removing it', yaml_data)
            del yaml_data['id']

        if not 'id' in yaml_data:
            self.logger.warning('Freeze window %s does not have an id; generating one', yaml_data)
            generated_id = hashlib.sha1(json.dumps(yaml_data, sort_keys=True, default=str).encode('utf-8')).hexdigest()
            yaml_data['id'] = generated_id
        else:
            # Replace spaces by underscores
            yaml_data['id'] = yaml_data['id'].replace(' ', '_')
            # Remove any character that wouldn't go in a branch name
            yaml_data['id'] = re.sub(r'[^a-zA-Z0-9\-_]', '', yaml_data['id'])

        self._id = yaml_data['id']

    @property
    def id(self):
        return self._id

    @property
    def only(self):
        return self._repo_only

    @property
    def include(self):
        return self._repo_include

    @property
    def repositories(self):
        return RepositoryList().extend(self._repo_only).extend(self._repo_include)

    @property
    def exclude(self):
        return self._repo_exclude

    @property
    def reason(self):
        return self._reason

    @property
    def from_date(self):
        return self._from

    @property
    def to_date(self):
        return self._to

    def get_approvers(self, extra_approvers=None, at=None):
        approvers = self._approvers + clean_approvers(force_list(extra_approvers))
        return list(set(a.handle for a in approvers if at is None or a.applies_to(at)))

    def get_reviewers(self, extra_approvers=None, at=None):
        approvers = self._approvers + clean_approvers(force_list(extra_approvers))
        return list(set(a.handle for a in approvers
                        if a.reviewer and (at is None or a.applies_to(at))))

    def all_reviewers(self, extra_approvers=None):
        approvers = self._approvers + clean_approvers(force_list(extra_approvers))
        return sorted((a for a in approvers if a.reviewer),
                      key=lambda a: (a.from_date, a.to_date, a.handle.lower()))

    def matches(self, repository, is_global_repository=False):
        repo_matches = self._repo_only.matches(repository) or \
            self._repo_include.matches(repository) or \
            (is_global_repository and not self._repo_only and not self._repo_exclude.matches(repository))

        return repo_matches

    def matches_with_branch(self, repository, branch, is_global_repository=False):
        repo_matches = self._repo_only.matches_with_branch(repository, branch) or \
            self._repo_include.matches_with_branch(repository, branch) or \
            (is_global_repository and not self._repo_only and not self._repo_exclude.matches_with_branch(repository, branch))

        return repo_matches

    def applies_to(self, date):
        return self._from <= date and self._to > date

    def current_or_future(self, date):
        return self._to > date

    def with_extra_approvers(self, extra_approvers):
        return FreezeWindow({
            'id': self._id,
            'from': self._from,
            'to': self._to,
            'reason': self._reason,
            'approvers': self._approvers + clean_approvers(force_list(extra_approvers)),
            'only': self._repo_only,
            'include': self._repo_include,
            'exclude': self._repo_exclude,
        })

    def valid_approver(self, approver, at=None):
        return any(a.lower() == approver.lower() for a in self.get_approvers(at=at))

    def __repr__(self):
        return "FreezeWindow(id={}, from={}, to={}, reason={})".format(
            self._id,
            self._from,
            self._to,
            self._reason,
        )

