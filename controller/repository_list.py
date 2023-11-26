import logging
import re

from repository import Repository


class RepositoryList(object):
    def __init__(self, yaml_data=None, default_org=None):
        self.logger = logging.getLogger('repository-list')

        self._default_org = default_org
        self._repositories = {}

        if yaml_data is None:
            return

        if isinstance(yaml_data, str):
            yaml_data = [yaml_data]

        if not isinstance(yaml_data, list) and not isinstance(yaml_data, RepositoryList):
            raise RuntimeError("Repository list definition '{}' is not a list".format(yaml_data))

        self.extend(yaml_data)

    # Override 'not' operator so it returns True if the list
    # of repositories is empty
    def __bool__(self):
        return bool(self._repositories)

    def __repr__(self):
        return "RepositoryList({})".format(
            list(self._repositories.values()),
        )

    def __iter__(self):
        return iter(self._repositories.values())

    def __len__(self):
        return len(self._repositories)

    @property
    def repositories(self):
        return list(self._repositories.values())

    def extend(self, other):
        for repository in other:
            self.add(repository)
        return self

    def add(self, repository, branches=None):
        if branches is not None and not isinstance(repository, str):
            raise RuntimeError("Cannot provide branches when repository is not a string")
        elif not isinstance(repository, Repository):
            if branches:
                repository = {
                    "handle": repository,
                    "branches": branches,
                }
            repository = Repository(repository, self._default_org)

        existing = self._repositories.get(repository.handle)
        if existing:
            existing.extend(repository)
            return

        self._repositories[repository.handle] = repository

    def matches(self, repository):
        return any(r.matches(repository) for r in self._repositories.values())

    def matches_with_branch(self, repository, branch):
        return any(r.matches_with_branch(repository, branch) for r in self._repositories.values())

    def split_pattern_matching(self):
        with_pattern_matching = RepositoryList()
        without_pattern_matching = RepositoryList()

        for repository in self._repositories.values():
            if repository.is_pattern:
                with_pattern_matching.add(repository)
            else:
                without_pattern_matching.add(repository)

        return with_pattern_matching, without_pattern_matching

