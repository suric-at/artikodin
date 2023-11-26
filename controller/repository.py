import fnmatch
import logging
import re

from utils import force_list, has_pattern_matching


class Repository(object):
    def __init__(self, yaml_data, default_org=None):
        self.logger = logging.getLogger('repository')

        if isinstance(yaml_data, str):
            yaml_data = {'handle': yaml_data}

        if not isinstance(yaml_data, dict):
            raise RuntimeError("Repository definition '{}' is not a string or a dictionary".format(yaml_data))

        if 'handle' not in yaml_data:
            raise RuntimeError("Repository definition '{}' does not have a 'handle'".format(yaml_data))

        handle = yaml_data['handle']
        if not isinstance(handle, str):
            raise RuntimeError("Repository handle '{}' is not a string".format(handle))

        handle = handle.lower()
        if not '/' in handle:
            if not default_org:
                raise RuntimeError("Repository handle '{}' does not have an organization and no default organization is set".format(handle))

            handle = '{}/{}'.format(default_org, handle)

        org, name = handle.split('/', 1)
        if has_pattern_matching(org):
            raise RuntimeError("Repository handle '{}' has a pattern in the organization".format(handle))

        if 'branches' not in yaml_data or yaml_data['branches'] is None:
            branches = None
        else:
            branches = force_list(yaml_data['branches'])
            if len(branches) == 0:
                raise RuntimeError("Repository definition '{}' has no branches; if this is intended, unset the branches parameter or set it to null".format(yaml_data))

            for branch in branches:
                if not isinstance(branch, str):
                    raise RuntimeError("Branch '{}' is not a string".format(branch))

                if has_pattern_matching(branch):
                    raise RuntimeError("Branch '{}' is a pattern".format(branch))

        self._handle = handle
        self._org = org
        self._name = name
        self._branches = set([b.lower() for b in branches]) if branches else None
        self._is_pattern = has_pattern_matching(self._handle)

    def __repr__(self):
        return "Repository(handle={}, branches={})".format(
            self._handle,
            '*' if self._branches is None else self._branches,
        )

    def __iter__(self):
        return iter(self._branches)

    def __in__(self, branch):
        return branch in self._branches

    @property
    def handle(self):
        return self._handle

    @property
    def org(self):
        return self._org

    @property
    def name(self):
        return self._name

    @property
    def is_pattern(self):
        return self._is_pattern

    @property
    def branches(self):
        return self._branches

    def extend(self, other):
        if not isinstance(other, Repository):
            raise RuntimeError("Cannot extend repository with {}".format(other))

        if self._handle != other._handle:
            raise RuntimeError("Cannot extend repository with {}".format(other))

        if self._branches is None:
            # Nothing to do, we already match all branches
            return self

        if other._branches is None:
            self._branches = None
            return self

        self._branches.update(other._branches)
        return self

    def matches(self, repository):
        if isinstance(repository, Repository):
            repository = repository.handle
        return fnmatch.fnmatch(repository, self._handle)

    def matches_with_branch(self, repository, branch):
        if not self.matches(repository):
            return False

        if self._branches is None:
            return True

        if callable(branch):
            branch = branch()

        return branch.lower() in self._branches

