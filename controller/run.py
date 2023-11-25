#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This script checks if we are currently in a freeze window,
# that applies for the requested repository. If so, it will
# exit with a non-zero exit code and print parameters that
# can be used to inform the user about the freeze.

from github import Github, GithubIntegration, Auth
from pprint import pprint as pp
import argparse
import datetime
import fnmatch
import github
import hashlib
import json
import logging
import os
import re
import requests
import sys
import yaml
import time


CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
GIT_DIR = os.path.join(CURRENT_DIR, '..')
CONFIG_DIR = os.path.join(GIT_DIR, 'configuration')
SCHEDULES_DIR = os.path.join(CONFIG_DIR, 'schedules')
TEMPLATES_DIR = os.path.join(CURRENT_DIR, 'templates')


class GithubApp(object):
    def __init__(self, app_id, private_key):
        self.logger = logging.getLogger('github-app')
        self.logger.info('Creating GithubApp object')

        ghauth = Auth.AppAuth(app_id, private_key)
        ghi = GithubIntegration(auth=ghauth)
        installation = ghi.get_installations()[0]
        self.__gh = installation.get_github_for_installation()
        #TODO: add permissions when getting a token? we would need to select both repositories we need
        #  self.__access_token = ghi.get_access_token(installation.id)
        #  self.__gh = Github(self.__access_token.token)

    def revoke(self):
        self.logger.info('Revoking token')
        return self.requester.requestJsonAndCheck('DELETE', "https://api.github.com/installation/token")

    def create_empty_root_commit(self, repo, message="Initial commit"):
        self.logger.info('Creating (empty) root commit')
        headers, data = self.requester.requestJsonAndCheck(
            'POST',
            "https://api.github.com/repos/{}/git/commits".format(repo),
            input={
                'message': message,
                'tree': '4b825dc642cb6eb9a060e54bf8d69288fbee4904',
                'parents': [],
            },
        )
        return data['sha']

    # Return a requester object with the token
    @property
    def requester(self):
        return self.__gh._Github__requester

    # Redirect all unknown calls to the self.__gh object
    def __getattr__(self, name):
        return getattr(self.__gh, name)


def matches(repository, patterns):
    return any(fnmatch.fnmatch(repository, pattern) for pattern in patterns)


def force_list(value):
    if isinstance(value, list):
        return value
    elif isinstance(value, str):
        return [value]
    else:
        return []


def clean_approvers(approvers):
    valid_approvers = []

    for approver in approvers:
        if isinstance(approver, str):
            approver = {'handle': approver}
        elif not isinstance(approver, dict):
            continue
        elif 'handle' not in approver:
            continue

        valid_approvers.append(approver)

    return valid_approvers


def cleanup_invalid_repositories(repositories, default_org=None):
    logger = logging.getLogger('cleanup-invalid-repositories')

    repos = []
    for repository in repositories:
        if not isinstance(repository, str):
            logger.warning('Skipping repository %s because it is not a string', repository)
            continue

        if not '/' in repository:
            if not default_org:
                logger.warning('Skipping repository %s because no default organization is set', repository)
                continue

            repos.append('{}/{}'.format(default_org, repository))

        org = repository.split('/', 1)[0]
        if has_pattern_matching(org):
            logger.warning('Skipping repository %s because the organization is a pattern', repository)
            continue

        repos.append(repository)

    return repos


class FreezeWindow(object):
    def __init__(self, yaml_data, default_org=None):
        # Skip if there is no from or no to
        if 'from' not in yaml_data or 'to' not in yaml_data:
            raise RuntimeError("window definition does not have 'from' or 'to'")

        self.logger = logging.getLogger('freeze-window')

        self._reason = yaml_data.get('reason')
        self._from = yaml_data['from']
        self._to = yaml_data['to']

        self._approvers = clean_approvers(force_list(yaml_data.get('approvers')))

        # Cleanup invalid repositories from the lists
        self._repo_only = yaml_data['only'] = \
            cleanup_invalid_repositories(force_list(yaml_data.get('only')), default_org)
        self._repo_include = yaml_data['include'] = \
            cleanup_invalid_repositories(force_list(yaml_data.get('include')), default_org)
        self._repo_exclude = yaml_data['exclude'] = \
            cleanup_invalid_repositories(force_list(yaml_data.get('exclude')), default_org)

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
        return list(set(self._repo_only + self._repo_include))

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

    @property
    def approvers(self):
        return list(set(a['handle'] for a in self._approvers))

    @property
    def reviewers(self):
        return list(set(a['handle'] for a in self._approvers if a.get('reviewer')))

    def get_approvers(self, extra_approvers=None):
        approvers = self._approvers + clean_approvers(force_list(extra_approvers))
        return list(set(a['handle'] for a in approvers))

    def get_reviewers(self, extra_approvers=None):
        approvers = self._approvers + clean_approvers(force_list(extra_approvers))
        return list(set(a['handle'] for a in approvers if a.get('reviewer')))

    def matches(self, repository, is_global_repository=False):
        repo_matches = matches(repository, self._repo_only) or \
            matches(repository, self._repo_include) or \
            (is_global_repository and not self._repo_only and not matches(repository, self._repo_exclude))

        return repo_matches

    def applies_to(self, date):
        return self._from <= date and self._to > date

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

    def valid_approver(self, approver):
        return any(a.lower() == approver.lower() for a in self.approvers)

    def __repr__(self):
        return "FreezeWindow(id={}, from={}, to={}, reason={})".format(
            self._id,
            self._from,
            self._to,
            self._reason,
            self._approvers,
            self._repo_only,
            self._repo_include,
            self._repo_exclude,
        )


class ConfigData(object):
    def __init__(self, default_org=None):
        self._default_org = default_org

        self._global_repositories = None
        self._global_approvers = None
        self._all_freeze_windows = None
        self._controller = None

        self.logger = logging.getLogger('config-data')

    def check(self):
        # Check loading the controller configuration
        self.controller

        # Check loading the global repositories
        self.global_repositories

        # Check loading the global approvers
        self.global_approvers

        # Check loading the freeze windows
        self.freeze_windows

    @property
    def global_repositories(self):
        if self._global_repositories is None:
            self._global_repositories = self.__get_global_repositories()
        return self._global_repositories

    @property
    def global_approvers(self):
        if self._global_approvers is None:
            self._global_approvers = self.__get_global_approvers()
        return self._global_approvers

    @property
    def freeze_windows(self):
        if self._all_freeze_windows is None:
            self._all_freeze_windows = list(self.__get_all_freeze_windows())
        return self._all_freeze_windows

    @property
    def controller(self):
        if self._controller is None:
            self._controller = self.__get_controller_config()
        return self._controller

    @property
    def exceptions_base_branch(self):
        return self.controller['exceptions']['base_branch']

    @property
    def exceptions_branch_format(self):
        return self.controller['exceptions']['branch_format']

    @property
    def exceptions_branch_regex(self):
        return re.compile("^{}$".format(self.exceptions_branch_format.
            replace('{repository}', r'(?P<repository>.+)').
            replace('{pr_num}', r'(?P<pr_num>\d+)')))

    @property
    def exceptions_branch_prefix(self):
        if not hasattr(self, '_exceptions_branch_prefix'):
            # Get all characters from the branch format until the first '{'
            self._exceptions_branch_prefix = self.exceptions_branch_format[:self.exceptions_branch_format.index('{')]
        return self._exceptions_branch_prefix

    @property
    def commit_status_context(self):
        return self.controller['status']['context']

    @property
    def active_windows_base_branch(self):
        return self.controller['windows']['base_branch']

    @property
    def active_windows_branch_format(self):
        return self.controller['windows']['branch_format']

    @property
    def active_windows_branch_regex(self):
        return re.compile("^{}$".format(self.active_windows_branch_format.
            replace('{freeze_window_id}', r'(?P<freeze_window_id>[a-zA-Z0-9\-_]+)')))

    @property
    def active_windows_branch_prefix(self):
        if not hasattr(self, '_active_windows_branch_prefix'):
            # Get all characters from the branch format until the first '{'
            self._active_windows_branch_prefix = self.active_windows_branch_format[:self.active_windows_branch_format.index('{')]
        return self._active_windows_branch_prefix

    @property
    def labels(self):
        return set(label for labels in self.controller['labels'].values() for label in labels)

    @property
    def labels_base(self):
        return set(self.controller['labels']['base'])

    @property
    def labels_pending(self):
        return self.labels_base | set(self.controller['labels']['pending'])

    @property
    def labels_requested(self):
        return self.labels_base | set(self.controller['labels']['requested'])

    @property
    def labels_approved(self):
        return self.labels_base | set(self.controller['labels']['approved'])

    @property
    def labels_rejected(self):
        return self.labels_base | set(self.controller['labels']['rejected'])

    @property
    def labels_target_merged(self):
        return set(self.controller['labels']['target_merged'])

    @property
    def labels_target_closed(self):
        return set(self.controller['labels']['target_closed'])

    def is_exception_requested(self, labels):
        labels = set(labels)
        return any(
            labels & expected_labels == expected_labels
            for expected_labels in [
                set(self.controller['labels']['requested']),
                set(self.controller['labels']['approved']),
                set(self.controller['labels']['rejected']),
            ]
        )

    @property
    def labels_exception_is_requested(self):
        return self.labels_base + set(self.controller['labels']['requested'])

    def __get_controller_config(self):
        config_controller_path = os.path.join(CONFIG_DIR, 'controller.yaml')
        if not os.path.exists(config_controller_path):
            raise RuntimeError("Controller configuration file does not exist")

        with open(config_controller_path, 'r') as f:
            config = yaml.safe_load(f)

            configuration_errors = self.__check_controller_config(config)
            if configuration_errors:
                raise RuntimeError("Controller configuration is invalid:\n - {}".format('\n - '.join(configuration_errors)))

            return config

    def __check_controller_config(self, config):
        validate_dict = lambda v: isinstance(v, dict)
        validate_str = lambda v: isinstance(v, str)
        validate_nonempty_list = lambda v: isinstance(v, list) and len(v) > 0

        def validate_branch_name(*formats):
            def branch_validator(value):
                if not isinstance(value, str):
                    return False

                check_value = value
                if formats:
                    # Check that the branch has a prefix
                    if value.startswith('{'):
                        raise RuntimeError("branch name '{}' cannot start with a parameter".format(value))

                    # Check that the branch has all the required formats
                    for f in formats:
                        formatted = '{{{}}}'.format(f)
                        if formatted not in value:
                            raise RuntimeError("missing format '{}' in branch name '{}'".format(f, value))
                        check_value = check_value.replace(formatted, 'xxx')

                # Check that the branch name only contains valid characters
                if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-_/]*[a-zA-Z0-9])?$', check_value):
                    print("CHECK VALUE IS {}".format(check_value))
                    raise RuntimeError("invalid characters in branch name '{}'".format(value))

                return True

            return branch_validator

        validators = {
            'exceptions': {
                '_validate': validate_dict,
                'base_branch': {
                    '_validate': validate_branch_name(),
                },
                'branch_format': {
                    '_validate': validate_branch_name('repository', 'pr_num'),
                },
            },
            'status': {
                '_validate': validate_dict,
                'context': {
                    '_validate': validate_str,
                },
            },
            'windows': {
                '_validate': validate_dict,
                'base_branch': {
                    '_validate': validate_branch_name(),
                },
                'branch_format': {
                    '_validate': validate_branch_name('freeze_window_id'),
                },
            },
            'labels': {
                '_validate': validate_dict,
                'base': {
                    '_validate': validate_nonempty_list,
                },
                'approved': {
                    '_validate': validate_nonempty_list,
                },
                'rejected': {
                    '_validate': validate_nonempty_list,
                },
                'requested': {
                    '_validate': validate_nonempty_list,
                },
                'pending': {
                    '_validate': validate_nonempty_list,
                },
                'target_merged': {
                    '_validate': validate_nonempty_list,
                },
                'target_closed': {
                    '_validate': validate_nonempty_list,
                },
            },
        }

        def recursive_validate_configuration(validators, cfg):
            errors = []

            for k, v in cfg.items():
                if k not in validators:
                    errors.append("unknown configuration key '{}'".format(k))
                    continue

                if '_validate' in validators[k]:
                    try:
                        if not validators[k]['_validate'](v):
                            errors.append("invalid value for configuration key '{}'".format(k))
                    except RuntimeError as e:
                        errors.append("invalid value for configuration key '{}': {}".format(k, e))

                if isinstance(v, dict):
                    errors.extend(recursive_validate_configuration(validators[k], v))

            return errors

        return recursive_validate_configuration(validators, config)

    def __get_global_repositories(self):
        config_repositories_path = os.path.join(CONFIG_DIR, 'repositories.yaml')
        if os.path.exists(config_repositories_path):
            with open(config_repositories_path, 'r') as f:
                contents = yaml.safe_load(f)
                list_contents = force_list(contents)
                cleaned_contents = cleanup_invalid_repositories(list_contents, self._default_org)
                return cleaned_contents
        return []

    def __get_global_approvers(self):
        config_approvers_path = os.path.join(CONFIG_DIR, 'approvers.yaml')
        if os.path.exists(config_approvers_path):
            with open(config_approvers_path, 'r') as f:
                return force_list(yaml.safe_load(f))
        return []

    def __get_all_freeze_windows(self):
        for root, dirs, files in os.walk(SCHEDULES_DIR):
            # Load the file as YAML
            for file in files:
                if not file.endswith('.yaml'):
                    continue

                with open(os.path.join(root, file), 'r') as f:
                    window = yaml.safe_load(f)

                    try:
                        yield FreezeWindow(window, self._default_org)
                    except RuntimeError as e:
                        logging.getLogger('config-data').warning('Skipping freeze window %s: %s', file, e)
                        continue

    def find_active_freeze_window_for(self, repository):
        now = datetime.datetime.now(datetime.timezone.utc)

        # Check if the repository is in the globally defined repositories
        global_repository = matches(repository, self.global_repositories)

        # Find all files in the schedules directory, recursively
        for window in self.freeze_windows:
            if not window.matches(repository, global_repository):
                continue

            if window.applies_to(now):
                return window.with_extra_approvers(self.global_approvers)


def split_pattern_matching(list_values):
    with_pattern_matching = []
    without_pattern_matching = []

    for value in list_values:
        if has_pattern_matching(value):
            with_pattern_matching.append(value)
        else:
            without_pattern_matching.append(value)

    return with_pattern_matching, without_pattern_matching


def has_pattern_matching(value):
    return any(c in value for c in ['*', '?', '['])


def format_template(template_name, template_args):
    template_path = os.path.join(TEMPLATES_DIR, template_name)

    if not os.path.exists(template_path):
        raise RuntimeError("Template {} does not exist".format(template_path))

    with open(template_path, 'r') as f:
        template = f.read()

    return template.format(**template_args)


class Run(object):
    def __init__(self, gh, args, cfg=None):
        self.gh = gh
        self.args = args
        self.logger = logging.getLogger('run')
        self.cfg = cfg or ConfigData(default_org=self.args.controller_repository_owner)

        self._cached_repo_branches = {}

    def repo_branches(self, repo, refresh=False):
        if not refresh and repo.full_name in self._cached_repo_branches:
            return self._cached_repo_branches[repo.full_name]

        self.logger.info('Getting branches for repository %s', repo.full_name)
        branches = list(repo.get_branches())

        self._cached_repo_branches[repo.full_name] = branches

        return branches

    def _check_freeze(self):
        self.logger.info('Checking if repository %s is in a freeze window', self.args.repository)
        freeze_window = self.cfg.find_active_freeze_window_for(self.args.repository)
        if not freeze_window:
            self.logger.info('No freeze window found that applies to repository %s', self.args.repository)
            return

        self.logger.info('Found freeze window that applies to repository %s: %s', self.args.repository, freeze_window)
        return freeze_window

    def _create_exception_request_pr(self, freeze_window, target_pr, exception_request_pr_branch):
        self.logger.info('Exception request pull request %s does not exist', exception_request_pr_branch)

        # Prepare the exception request body
        template_args = {
            'target_repository': self.args.repository,
            'target_repository_owner': self.args.repository_owner,
            'target_repository_name': self.args.repository_name,
            'target_pr_num': self.args.pull_request,
            'target_pr_url': target_pr.html_url,
            'target_pr_title': target_pr.title,
            'target_pr_body': target_pr.body,
            'target_pr_author_login': target_pr.user.login,
            'target_pr_author_name': target_pr.user.name,
            'freeze_reason': freeze_window.reason,
            'freeze_from': freeze_window.from_date.isoformat(),
            'freeze_to': freeze_window.to_date.isoformat(),
            'freeze_details': "{}until {}".format(
                "for {} ".format(freeze_window.reason) if freeze_window.reason else "",
                freeze_window.to_date.isoformat(),
            ),
        }
        exception_request_body = format_template('exception-request-body.md', template_args)
        exception_request_title = format_template('exception-request-title.md', template_args)

        # Get the controller repository
        ctrl_repo = self.gh.get_repo(self.args.controller_repository, lazy=True)

        # Get the exceptions branch
        self.logger.info('Getting exceptions branch %s', self.cfg.exceptions_base_branch)
        exceptions_branch = ctrl_repo.get_branch(branch=self.cfg.exceptions_base_branch)

        # Check if the exceptions branch exists
        try:
            self.logger.info('Checking if exception request branch %s exists', self.cfg.exceptions_base_branch)
            new_branch = ctrl_repo.get_branch(branch=exception_request_pr_branch)

            self.logger.info('Get ref to exception request branch %s', exception_request_pr_branch)
            new_branch_ref = ctrl_repo.get_git_ref(ref=f"heads/{exception_request_pr_branch}")
        except github.GithubException as e:
            if e.status != 404:
                raise

            self.logger.info('Creating exception request branch %s', self.cfg.exceptions_base_branch)

            # Create a new branch from the exceptions branch
            self.logger.info('Creating new branch %s', exception_request_pr_branch)
            new_branch_ref = ctrl_repo.create_git_ref(
                ref=f"refs/heads/{exception_request_pr_branch}",
                sha=exceptions_branch.commit.sha,
            )

            # Get the new branch
            retries = 5
            while retries > 0:
                try:
                    self.logger.info('Getting new branch %s', exception_request_pr_branch)
                    new_branch = ctrl_repo.get_branch(branch=exception_request_pr_branch)
                    break
                except github.GithubException as e:
                    if e.status != 404:
                        raise

                    retries -= 1
                    if retries == 0:
                        raise

                    self.logger.info('Branch %s does not exist yet; retrying', exception_request_pr_branch)
                    time.sleep(1)
                    continue

        # Get the parent commit
        self.logger.info('Getting parent commit')
        parent_commit = ctrl_repo.get_git_commit(sha=exceptions_branch.commit.sha)

        # Create a new empty commit in the new branch
        self.logger.info('Creating new commit in branch %s', exception_request_pr_branch)
        new_commit = ctrl_repo.create_git_commit(
            message=f"Add exception request for {self.args.repository}#{self.args.pull_request}",
            tree=new_branch.commit.commit.tree,
            parents=[parent_commit],
        )

        # Edit the branch to point to the new commit
        self.logger.info('Updating branch %s to point to new commit %s', exception_request_pr_branch, new_commit.sha)
        new_branch_ref.edit(sha=new_commit.sha, force=True)

        # Create a new pull request
        self.logger.info('Creating new pull request for branch %s', exception_request_pr_branch)
        exception_request_pr = ctrl_repo.create_pull(
            title=exception_request_title,
            body=exception_request_body,
            base=self.cfg.exceptions_base_branch,
            head=exception_request_pr_branch,
        )

        # Add labels to pull request 'exceptions' and 'pending'
        self.logger.info('Adding labels to exception request pull request %s', exception_request_pr_branch)
        exception_request_pr.add_to_labels(*self.cfg.labels_pending)

        # Commenting on the target pull request
        template_args.update({
            'exception_request_pr_url': exception_request_pr.html_url,
        })
        target_pull_request_comment = format_template('target-pull-request-comment.md', template_args)
        self.logger.info('Commenting on target pull request %s', self.args.pull_request)
        target_pr.create_issue_comment(target_pull_request_comment)

        return {
            'exists': True,
            'approved': False,
            'requested': False,
            'moved_to_requested': False,
            'url': exception_request_pr.html_url,
        }

    def _check_exception_request_pr(self, freeze_window, create_if_missing=True, move_to_requested=False, best_effort=False):
        exception_request_pr_branch = self.cfg.exceptions_branch_format.format(
            repository=self.args.repository,
            pr_num=self.args.pull_request,
        )
        self.logger.info('Checking if exception request pull request %s exists', exception_request_pr_branch)

        ctrl_repo = self.gh.get_repo(self.args.controller_repository, lazy=True)
        exception_request_prs = list(ctrl_repo.get_pulls(
            base=self.cfg.exceptions_base_branch,
            head=f"{self.args.controller_repository_owner}:{exception_request_pr_branch}",
            state='open',
        ))
        if len(exception_request_prs) > 1:
            raise RuntimeError("Too many exception request PRs found for %s", exception_request_pr_branch)

        if len(exception_request_prs) == 0 and not create_if_missing:
            return {
                'exists': False,
                'approved': False,
                'requested': False,
                'moved_to_requested': False,
                'url': None,
            }

        # Get the target repo
        target_repo = self.gh.get_repo(self.args.repository, lazy=True)

        # Get the target pull request
        self.logger.info('Getting target pull request %s', self.args.pull_request)
        target_pr = target_repo.get_pull(self.args.pull_request)

        if len(exception_request_prs) == 0:
            if target_pr.state != 'open':
                if best_effort:
                    self.logger.info('Target pull request %s #%s is no longer open; ignoring',
                                     self.args.repository, self.args.pull_request)
                    return {
                        'skip_status_update': True,
                        'exists': False,
                        'approved': False,
                        'requested': False,
                        'moved_to_requested': False,
                        'url': None,
                    }

                raise RuntimeError("Target pull request %s #%s is no longer open",
                                   self.args.repository, self.args.pull_request)

            return self._create_exception_request_pr(freeze_window, target_pr, exception_request_pr_branch)

        exception_request_pr = exception_request_prs[0]
        self.logger.info('Exception request pull request %s exists: %s',
                         exception_request_pr_branch, exception_request_pr)

        # Check if the target pull request is still open
        if target_pr.state != 'open':
            # Close the exception request PR
            self.logger.info('Target pull request %s #%s is no longer open; '
                             'closing exception request %s',
                             self.args.repository, self.args.pull_request,
                             exception_request_pr_branch)
            exception_request_pr.create_issue_comment(
                'The target pull request is no longer open; '
                'closing this exception request')
            exception_request_pr.edit(state='closed')

            if target_pr.merged:
                self.logger.info('Adding target merged labels to exception request %s',
                                 self.cfg.labels_target_merged, exception_request_pr_branch)
                exception_request_pr.add_to_labels(*self.cfg.labels_target_merged)
            else:
                self.logger.info('Adding target closed labels to exception request %s',
                                 self.cfg.labels_target_closed, exception_request_pr_branch)
                exception_request_pr.add_to_labels(*self.cfg.labels_target_closed)

            # Delete the branch too
            try:
                self.logger.info('Deleting branch %s', exception_request_pr_branch)
                ctrl_repo.get_git_ref(ref=f"heads/{exception_request_pr_branch}").delete()
            except github.GithubException as e:
                if e.status != 404:
                    raise

                self.logger.info('Branch %s does not exist; ignoring', exception_request_pr_branch)

            return {
                'skip_status_update': True,
                'exists': False,
                'approved': False,
                'requested': False,
                'moved_to_requested': False,
                'url': None,
            }

        # Check if the exception request PR requires a title update
        expect_title = format_template('exception-request-title.md', {
            'target_repository': target_repo.full_name,
            'target_pr_num': target_pr.number,
            'target_pr_title': target_pr.title,
        })
        if exception_request_pr.title != expect_title:
            self.logger.info('Exception request %s title does not match the expected title; updating', exception_request_pr_branch)
            exception_request_pr.edit(title=expect_title)

        # Get the pull request reviews for the exception request
        self.logger.info('Getting reviews for exception request %s', exception_request_pr_branch)
        exception_request_pr_reviews = exception_request_pr.get_reviews()

        # Go over the reviews and keep only the latest review of each valid reviewer
        reviews = {}
        for review in exception_request_pr_reviews:
            reviewer_login = review.user.login
            review_state = review.state

            # Check if reviewer is an approver for the freeze window
            if not freeze_window.valid_approver(reviewer_login):
                self.logger.info('Reviewer %s is not an approver for freeze window; ignoring review', reviewer_login)
                continue

            # We only care about the latest review for each reviewer
            existing = reviews.get(reviewer_login)
            if existing is None or existing.submitted_at < review.submitted_at:
                reviews[reviewer_login] = review

        # Check if any review is requesting changes
        changes_requested = False
        approved = False
        for reviewer_login, review in reviews.items():
            if review.state == 'CHANGES_REQUESTED':
                self.logger.info('Reviewer %s requested changes', reviewer_login)
                changes_requested = True
            elif review.state == 'APPROVED':
                self.logger.info('Reviewer %s approved', reviewer_login)
                approved = True

        # Get the current labels
        self.logger.info('Checking if exception request %s has the expected labels', exception_request_pr_branch)
        exception_request_pr_labels = set([label.name for label in exception_request_pr.labels])

        # Some label logic
        non_controller_labels = [l for l in exception_request_pr_labels if l not in self.cfg.labels]
        requested = self.cfg.is_exception_requested(exception_request_pr_labels)

        # Check if the exception request needs to be moved to the 'requested' state
        moved_to_requested = move_to_requested and not requested
        if moved_to_requested:
            # Add the reviewers
            self.logger.info('Adding reviewers')
            exception_request_pr.create_review_request(reviewers=freeze_window.get_reviewers())

        # Compute the expected labels
        expected_labels = set(non_controller_labels)
        if changes_requested:
            expected_labels.update(self.cfg.labels_rejected)
        elif approved:
            expected_labels.update(self.cfg.labels_approved)
        elif len(reviews) > 0 or requested or moved_to_requested:
            expected_labels.update(self.cfg.labels_requested)
        else:
            expected_labels.update(self.cfg.labels_pending)

        # Check if the exception request has the expected labels
        if exception_request_pr_labels != expected_labels:
            self.logger.info('Exception request %s (#%d) does not have the expected labels', self.args.controller_repository, exception_request_pr.number)
            self.logger.info('Expected labels: %s', expected_labels)
            self.logger.info('Actual labels: %s', exception_request_pr_labels)
            self.logger.info('Updating exception request %s labels', exception_request_pr_branch)
            exception_request_pr.set_labels(*expected_labels)

        # Compute if the exception request is approved
        exception_approved = approved and not changes_requested

        return {
            'exists': True,
            'approved': exception_approved,
            'requested': requested or moved_to_requested,
            'moved_to_requested': moved_to_requested,
            'url': exception_request_pr.html_url,
        }

    def _push_status(self, allow, freeze_window, pr_status):
        target_repo = self.gh.get_repo(self.args.repository, lazy=True)

        # Get the commit, either from the input or from the pull request
        if self.args.commit:
            self.logger.info('Getting commit %s', self.args.commit)
            commit = target_repo.get_commit(self.args.commit)
        else:
            self.logger.info('Getting pull request %s', self.args.pull_request)
            pr = target_repo.get_pull(self.args.pull_request)

            self.logger.info('Getting commit %s (head of pull request)', pr.head.sha)
            commit = target_repo.get_commit(pr.head.sha)

        # Prepare the status description
        if not allow and not pr_status.get('exists'):
            state = 'failure'
            description = 'Error creating exception request pull request'
        elif allow and not freeze_window:
            state = 'success'
            description = 'The repository is not frozen'
        elif allow and freeze_window:
            state = 'success'
            description = 'Exception approved to bypass the freeze{}'.format(
                ' ({})'.format(freeze_window.reason) if freeze_window.reason else '')
        else:
            state = 'error'
            description = 'The repository is frozen{}{}'.format(
                ' ({})'.format(freeze_window.reason) if freeze_window.reason else '',
                ' - exception pending approval' if pr_status.get('requested') else '',
            )

        # Push the status to the commit
        create_status_kwargs = {
            'state': state,
            'description': description,
            'context': self.cfg.commit_status_context,
        }
        if pr_status.get('url'):
            create_status_kwargs['target_url'] = pr_status.get('url')

        self.logger.info('Pushing status to commit %s: %s', commit.sha, create_status_kwargs)
        commit.create_status(**create_status_kwargs)

    def _get_or_create_active_windows_root_branch(self):
        # Get the controller repository
        ctrl_repo = self.gh.get_repo(self.args.controller_repository, lazy=True)

        # Get the active windows empty root branch
        self.logger.info('Getting %s branch', self.cfg.active_windows_base_branch)
        try:
            return ctrl_repo.get_branch(branch=self.cfg.active_windows_base_branch)
        except github.GithubException as e:
            if e.status != 404:
                raise

        self.logger.info('Creating %s (root) branch', self.cfg.active_windows_base_branch)

        # Get the empty tree
        # Create new root empty commit
        self.logger.info('Creating new (empty) root commit')
        root_commit_sha = self.gh.create_empty_root_commit(
            ctrl_repo.full_name,
            'Root commit for the branch to keep track of active freeze windows',
        )

        # Create new branch from root commit
        self.logger.info('Creating new branch %s', self.cfg.active_windows_base_branch)
        active_windows_branch = ctrl_repo.create_git_ref(
            ref='refs/heads/{}'.format(self.cfg.active_windows_base_branch),
            sha=root_commit_sha,
        )

        # Get the active_windows branch
        self.logger.info('Getting %s branch', self.cfg.active_windows_base_branch)
        return ctrl_repo.get_branch(branch=self.cfg.active_windows_base_branch)

    def _freeze_repository(self, repository, max_age_days=90):
        # Get all the pull requests from the repository that:
        # - are open
        # - are mergeable
        # - are against 'main'

        # Get the repository
        target_repo = self.gh.get_repo(repository, lazy=True)

        # Get and filter the pull requests
        self.logger.info('Getting pull requests for repository %s', repository)
        pull_requests = list(target_repo.get_pulls(
            state='open',
            base='main',
            sort='created',
            direction='desc',
        ))

        for pr in pull_requests:
            # Check if the pull request is older than the max age
            if (datetime.datetime.now(datetime.timezone.utc) - pr.created_at).days > max_age_days:
                break

            if not pr.mergeable:
                continue

            # Get the commit
            self.logger.info('Getting commit %s', pr.head.sha)
            commit = target_repo.get_commit(pr.head.sha)

            # Freeze the pull request
            self.logger.info('Freezing pull request %s #%s', repository, pr.number)
            commit.create_status(
                state='error',
                description='The repository is frozen',
                context=self.cfg.commit_status_context,
            )

    def _activate_freeze_windows(self, freeze_windows, affected_repositories):
        if not freeze_windows:
            return

        self.logger.info('Activating %s freeze windows', len(freeze_windows))

        # Get the controller repository
        ctrl_repo = self.gh.get_repo(self.args.controller_repository, lazy=True)

        # Get the active windows empty root branch
        active_windows_branch = self._get_or_create_active_windows_root_branch()

        # Already frozen repositories
        already_frozen_repositories = set()

        for freeze_window in freeze_windows:
            # Identify which of the repositories are affected by this freeze window
            repositories = [r for r, windows in affected_repositories.items()
                            if freeze_window.id in windows]

            # Go over the repositories, and freeze them
            self.logger.info('Freezing %d repositories', len(repositories))
            for repository in repositories:
                self._freeze_repository(repository)
                del affected_repositories[repository]

            # Create a new branch from the active windows branch
            freeze_window_branch_name = self.cfg.windows_branch_format.format(
                freeze_window_id=freeze_window.id,
            )
            self.logger.info('Creating new branch %s', freeze_window_branch_name)
            new_branch_ref = ctrl_repo.create_git_ref(
                ref='refs/heads/{}'.format(freeze_window_branch_name),
                sha=active_windows_branch.commit.sha,
            )

    def _unfreeze_repository(self, repository, max_age_days=90):
        # To unfreeze a repository, we need to:
        #  - List the controller repository branches that match an exception request
        #    for the repository
        #  - For each of these branches:
        #    - Get the pull request that corresponds to the exception request branch
        #      - Comment on the pull request to indicate that no freeze window applies anymore
        #      - Close the pull request
        #      - Delete the branch
        #    - Get the target repository pull request
        #      - Lift the freeze on the pull request
        #      - Post a comment on the pull request to indicate that it was unfrozen
        #  - Optionally, go over all open pull requests that are mergeable and unfreeze them

        # Get the controller repository
        ctrl_repo = self.gh.get_repo(self.args.controller_repository, lazy=True)

        # Get the exception request branches
        all_branches = self.repo_branches(ctrl_repo)

        # Prepare this so we don't build that object twice
        target_repo = self.gh.get_repo(repository, lazy=True)

        # Go over the branches and find the ones that match the repository
        for branch in all_branches:
            m = self.cfg.exceptions_branch_regex.match(branch.name)
            if not m or m.group('repository') != repository:
                continue

            # Get the exception request pull request
            self.logger.info('Getting exception request pull request %s', branch.name)
            exception_request_prs = list(ctrl_repo.get_pulls(
                base=self.cfg.exceptions_base_branch,
                head=f"{self.args.controller_repository_owner}:{branch.name}",
                state='open',
            ))
            if len(exception_request_prs) > 1:
                raise RuntimeError("Too many exception request PRs found for %s", branch.name)

            if len(exception_request_prs) != 0:
                exception_request_pr = exception_request_prs[0]

                # Comment on the pull request to indicate that no freeze window applies anymore
                self.logger.info('Commenting on exception request pull request %s', branch.name)
                exception_request_pr.create_issue_comment(
                    "The freeze window that this exception request was created "
                    "for is no longer active; closing")

                # Close the pull request
                self.logger.info('Closing exception request pull request %s', branch.name)
                exception_request_pr.edit(state='closed')

            # Delete the branch
            try:
                self.logger.info('Deleting branch %s', branch.name)
                ctrl_repo.get_git_ref(ref=f"heads/{branch.name}").delete()
            except github.GithubException as e:
                if e.status != 404:
                    raise

                self.logger.info('Branch %s does not exist; ignoring', branch.name)

            self.logger.info('Getting target pull request %s', m.group('pr_num'))
            target_pr = target_repo.get_pull(int(m.group('pr_num')))

            # Check if the pull request is still open
            if target_pr.state != 'open':
                self.logger.info(
                        'Target pull request %s #%s is no longer open; skipping',
                        repository, m.group('pr_num'))

                if target_pr.merged:
                    self.logger.info('Adding target merged labels to exception request %s', self.cfg.labels_target_merged, exception_request_pr_branch)
                    exception_request_pr.add_to_labels(*self.cfg.labels_target_merged)
                else:
                    self.logger.info('Adding target closed labels to exception request %s', self.cfg.labels_target_closed, exception_request_pr_branch)
                    exception_request_pr.add_to_labels(*self.cfg.labels_target_closed)

                continue

            # Get the git commit for the pull request
            self.logger.info('Getting commit %s', target_pr.head.sha)
            commit = target_repo.get_commit(target_pr.head.sha)

            # Lift the freeze on the pull request
            self.logger.info('Lifting freeze on pull request %s', m.group('pr_num'))
            commit.create_status(
                state='success',
                description='The repository is not frozen',
                context=self.cfg.commit_status_context,
            )

            # Post a comment on the pull request to indicate that it was unfrozen
            self.logger.info('Commenting on pull request %s', m.group('pr_num'))
            target_pr.create_issue_comment(
                "The freeze on this repository has been lifted; "
                "this pull request is no longer frozen. 🔥🔥🔥")

        # Only go over the pull requests that did not have an exception request
        # branch if the max age is greater than 0
        if max_age_days < 1:
            return

        # Get and filter the pull requests
        self.logger.info('Getting pull requests for repository %s', repository)
        pull_requests = list(target_repo.get_pulls(
            state='open',
            base='main',
            sort='created',
            direction='desc',
        ))

        for pr in pull_requests:
            # Check if the pull request is older than the max age
            if (datetime.datetime.now(datetime.timezone.utc) - pr.created_at).days > max_age_days:
                break

            if not pr.mergeable:
                continue

            # Get the commit
            self.logger.info('Getting commit %s', pr.head.sha)
            commit = target_repo.get_commit(pr.head.sha)

            # Unfreeze the pull request
            self.logger.info('Unfreezing pull request %s #%s', repository, pr.number)
            commit.create_status(
                state='success',
                description='The repository is not frozen',
                context=self.cfg.commit_status_context,
            )

    def _cleanup_freeze_windows(self, freeze_windows, affected_repositories):
        if not freeze_windows:
            return

        self.logger.info('Cleaning up %s freeze windows', len(freeze_windows))

        # Get the controller repository
        ctrl_repo = self.gh.get_repo(self.args.controller_repository, lazy=True)

        # Already unfrozen repositories
        already_unfrozen_repositories = set()

        for freeze_window in freeze_windows:
            # Identify which of the repositories are affected by this freeze window
            repositories = [r for r, windows in affected_repositories.items()
                            if freeze_window.id in windows]

            # Go over the repositories, and unfreeze them
            self.logger.info('Unfreezing %d repositories', len(repositories))
            for repository in repositories:
                self._unfreeze_repository(repository)
                del affected_repositories[repository]

            # Delete the branch
            freeze_window_branch_name = self.cfg.windows_branch_format.format(
                freeze_window_id=freeze_window.id,
            )
            self.logger.info('Deleting branch %s', freeze_window_branch_name)
            ctrl_repo.get_git_ref(ref=f"heads/{freeze_window_branch_name}").delete()

    def _get_affected_repositories(self, freeze_windows):
        all_affected_repositories = set()
        pattern_matchings = set()

        with_patterns, without_patterns = split_pattern_matching(self.cfg.global_repositories)
        all_affected_repositories.update(without_patterns)
        pattern_matchings.update(with_patterns)

        # Add both to activate and to cleanup to the same list
        for freeze_window in freeze_windows:
            # We don't need to check exclude, as we only need to know where this would apply
            repositories = freeze_window.repositories

            with_patterns, without_patterns = split_pattern_matching(repositories)
            all_affected_repositories.update([r for r in without_patterns if not matches(r, freeze_window.exclude)])
            pattern_matchings.update(with_patterns)

        # Now compute which of these are patterns for the organization, we
        # assume that no '/' means "same org as controller"
        orgs_patterns = {}
        for pattern in pattern_matchings:
            org = pattern.split('/', 1)[0]
            orgs_patterns.setdefault(org, set()).add(pattern)

        # If there is pattern matching, get the list of affected repositories
        # by listing all the repositories in all the organizations that we have
        if not pattern_matchings:
            for org_name, patterns in orgs_patterns.items():
                self.logger.info('Getting matching repositories from organization %s', org_name)
                org = self.gh.get_organization(org_name)
                matching_repos = [repo.full_name
                                  for repo in org.get_repos()
                                  if matches(repo.full_name, patterns)]
                all_affected_repositories.update(matching_repos)
                self.logger.info('Found %s matching repositories in organization %s', len(matching_repos), org_name)

        return all_affected_repositories

    def _split_affected_repositories(self, affected_repositories, already_active_freeze_windows, freeze_windows_to_activate, freeze_windows_to_cleanup):
        new_frozen_repositories = {}
        new_unfrozen_repositories = {}

        def select_windows_matching_repo(freeze_windows, repository):
            global_repository = matches(repository, self.cfg.global_repositories)
            for window in freeze_windows:
                if window.matches(repository, global_repository):
                    yield window

        for repository in affected_repositories:
            # Check if the repository is already frozen by an active freeze window
            if any(select_windows_matching_repo(already_active_freeze_windows.values(), repository)):
                self.logger.info('Repository %s is already frozen by an active freeze window, nothing is changing', repository)
                continue

            new_frozen_windows = list(select_windows_matching_repo(freeze_windows_to_activate.values(), repository))
            if new_frozen_windows:
                self.logger.info('Repository %s needs to be frozen', repository)
                new_frozen_repositories[repository] = [w.id for w in new_frozen_windows]
                continue

            new_unfrozen_windows = list(select_windows_matching_repo(freeze_windows_to_cleanup.values(), repository))
            if new_unfrozen_windows:
                self.logger.info('Repository %s needs to be unfrozen', repository)
                new_unfrozen_repositories[repository] = [w.id for w in new_unfrozen_windows]
                continue

        return new_frozen_repositories, new_unfrozen_repositories

    def update(self, move_to_requested=False, best_effort=False):
        allow = True
        pr_status = {}

        try:
            freeze_window = self._check_freeze()
            if freeze_window:
                pr_status = self._check_exception_request_pr(
                    freeze_window,
                    create_if_missing=not move_to_requested,
                    move_to_requested=move_to_requested,
                    best_effort=best_effort,
                )
                if not pr_status['approved']:
                    allow = False

                if move_to_requested and not pr_status['moved_to_requested']:
                    self.logger.warning('Did not move exception request to requested')
        except Exception as e:
            self.logger.exception(e)

            freeze_window = None
            allow = False

            raise
        finally:
            if not pr_status.get('skip_status_update'):
                self._push_status(allow, freeze_window, pr_status)

    def cron_update(self):
        now = datetime.datetime.now(datetime.timezone.utc)

        # For the cron update, we want to:
        #  - Check if we entered a freeze window that was not open before
        #  - Check if we left a freeze window that was open before
        #
        # To save that we are currently in a freeze window, we can create
        # a branch corresponding to the freeze window
        #
        # In both cases, we want to verify if there are any repositories
        # that weren't affected by the freeze window and that now are, in
        # which case we need to go over the open pull requests that are
        # mergeable for these repositories and add a status to them.
        # Note in that first case, we also need to check if any of the
        # repositories listed is using wildcard or pattern matching,
        # in which case we need to list all the repositories that match
        # the pattern in all the organizations that we have access to.
        #
        # We also want to check if there are any repositories that were
        # affected by the freeze window and that now aren't, in which case
        # we need to go over the exception pull requests that are open
        # and close them, as well as push a status to the pull request
        # to enable them to be merged.

        # Get all the freeze windows
        self.logger.info('Getting all freeze windows')
        freeze_windows = list(self.cfg.freeze_windows)

        # Split the active and inactive freeze windows
        active_freeze_windows = {}
        inactive_freeze_windows = {}
        for freeze_window in freeze_windows:
            # Check if the freeze window is active
            if freeze_window.applies_to(now):
                active_freeze_windows[freeze_window.id] = freeze_window
            else:
                inactive_freeze_windows[freeze_window.id] = freeze_window

        # Print the active and inactive freeze windows in the logs
        self.logger.info('Active freeze windows (%s)', len(active_freeze_windows))
        for freeze_window in active_freeze_windows.values():
            self.logger.info('  %s', freeze_window)
        self.logger.info('Inactive freeze windows (%s)', len(inactive_freeze_windows))
        for freeze_window in inactive_freeze_windows.values():
            self.logger.info('  %s', freeze_window)

        # Get the controller repository
        ctrl_repo = self.gh.get_repo(self.args.controller_repository, lazy=True)

        # Get all branches that match the active freeze windows
        all_branches = self.repo_branches(ctrl_repo)

        # Check if we entered or exited a freeze window
        freeze_windows_to_activate = {k: v for k, v in active_freeze_windows.items()}
        freeze_windows_to_cleanup = {}
        already_active_freeze_windows = {}
        for branch in all_branches:
            m = self.cfg.windows_branch_regex.match(branch.name)
            if not m:
                continue

            # Get the freeze window ID
            freeze_window_id = m.group('freeze_window_id')

            # If the freeze window is active and should be active, we can
            # remove it from the active freeze windows
            if freeze_window_id in active_freeze_windows:
                self.logger.info('Freeze window %s is active and should be active; nothing to do', freeze_window_id)
                already_active_freeze_windows[freeze_window_id] = active_freeze_windows[freeze_window_id]
                if freeze_window_id in freeze_windows_to_activate:
                    del freeze_windows_to_activate[freeze_window_id]
                continue

            # If the window is active and should not be active, we will need to
            # perform some cleanup, but only if that window still exists or we
            # won't be able to find the pull requests that were affected by it
            if freeze_window_id in inactive_freeze_windows:
                self.logger.info('Freeze window %s is active and should not be active; needs cleanup', freeze_window_id)
                freeze_windows_to_cleanup[freeze_window_id] = inactive_freeze_windows[freeze_window_id]
                continue

            # If we get here, it means that the freeze window is active but
            # should not be active, and that the freeze window does not exist
            # in the configuration anymore. This means that we can remove the
            # tag from the controller repository, but we won't be able to
            # perform any cleanup.
            self.logger.warning("Freeze window %s is active and should not be active, but does not exist anymore; removing branch but won't be able to cleanup", freeze_window_id)
            # This is not possible to call .delete() on the branch object directly
            ctrl_repo.get_git_ref(ref=f"heads/{branch.name}").delete()

        # If there's no freeze window to activate or cleanup, we are done
        if not freeze_windows_to_activate and not freeze_windows_to_cleanup:
            self.logger.info('No freeze windows to activate or cleanup; nothing to do')
            return

        # Get affected repositories
        affected_repositories = self._get_affected_repositories(
            list(freeze_windows_to_activate.values()) + list(freeze_windows_to_cleanup.values()))

        self.logger.debug('Affected repositories: %s', affected_repositories)

        # Split the affected repositories into those that need to be frozen
        # and those that need to be unfrozen
        new_frozen_repositories, new_unfrozen_repositories = self._split_affected_repositories(
            affected_repositories, already_active_freeze_windows, freeze_windows_to_activate, freeze_windows_to_cleanup)

        self.logger.debug('New frozen repositories: %s', new_frozen_repositories)
        self.logger.debug('New unfrozen repositories: %s', new_unfrozen_repositories)

        self.logger.info('Freeze windows to activate: %s', freeze_windows_to_activate)
        self.logger.info('Freeze windows to cleanup: %s', freeze_windows_to_cleanup)

        #  If there are any freeze windows left to activate, activate them
        if freeze_windows_to_activate:
            self._activate_freeze_windows(freeze_windows_to_activate.values(), new_frozen_repositories)

        if freeze_windows_to_cleanup:
            self._cleanup_freeze_windows(freeze_windows_to_cleanup.values(), new_unfrozen_repositories)


def main():
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(
        description='Check if we are in a freeze window.',
    )

    parser.add_argument(
        '--app-id',
        required=True,
        help='The application ID.',
    )

    private_key = parser.add_mutually_exclusive_group(required=True)
    private_key.add_argument(
        '--private-key',
        help='The private key.',
    )
    private_key.add_argument(
        '--private-key-file',
        help='The private key file.',
        type=lambda fpath: argparse.FileType('r')(fpath).read(),
        dest='private_key',
    )

    parser.add_argument(
        '--controller-repository',
        required=True,
        help='The repository where the controller is located.',
    )

    # Create subcommand 'update'
    subparsers = parser.add_subparsers(
        dest='operation',
        required=True,
    )

    update_parser = subparsers.add_parser(
        'update',
        help='Update the status of the pull request.',
    )
    update_parser.add_argument(
        '--best-effort',
        action='store_true',
        help='Do not fail if the target pull request cannot be found.',
    )
    update_parser.add_argument(
        '--controller-pull-request',
        type=int,
        help='The pull request number in the controller repository.',
    )
    update_parser.add_argument(
        '--head-ref',
        help='The head ref of the exception request pull request.',
    )
    update_parser.add_argument(
        '--repository',
        help='The repository to check.',
    )
    update_parser.add_argument(
        '--pull-request',
        type=int,
        help='The pull request to check.',
    )
    update_parser.add_argument(
        '--commit',
        required=False,  # If not provided, we'll get it from the pull request
        help='The commit to check.',
    )

    # Create subcommand 'cron'
    cron_parser = subparsers.add_parser(
        'cron',
        help='Run the cron job.',
    )

    # Create subcommand 'request-exception'
    request_parser = subparsers.add_parser(
        'request',
        help='Move a pending exception request into requested mode.',
    )
    request_parser.add_argument(
        '--controller-pull-request',
        type=int,
        help='The pull request number in the controller repository.',
    )
    request_parser.add_argument(
        '--head-ref',
        help='The head ref of the exception request pull request.',
    )
    request_parser.add_argument(
        '--repository',
        help='The repository to check.',
    )
    request_parser.add_argument(
        '--pull-request',
        type=int,
        help='The pull request to check.',
    )
    request_parser.add_argument(
        '--commit',
        help='The commit to check.',
    )

    # Create subcommand 'check-config'
    subparsers.add_parser(
        'check-config',
        help='Check the configuration and exit.',
    )

    args = parser.parse_args()

    def parse_repository(repository):
        owner, name = repository.split('/', 1)
        return owner, name

    args.controller_repository_owner, args.controller_repository_name = parse_repository(args.controller_repository)

    # Check the configuration
    cfg = ConfigData(default_org=args.controller_repository_owner)
    cfg.check()

    # If the operation is 'check-config', we are done
    if args.operation == 'check-config':
        return
    elif args.operation == 'request' or args.operation == 'update':
        # For a request, we allow to pass any of those combinations:
        #  - --controller-pull-request, which gives the pull request number in the controller repository
        #  - --head-ref, which gives the branch name in the controller repository
        #  - --repository and --pull-request, which gives the repository and pull request number
        #
        # We need to check that any of those combinations is provided, that no
        # more than one of those combinations is provided, and that
        # the provided values are valid.

        invalid_combinations = (
            ('controller_pull_request', 'head_ref'),
            ('controller_pull_request', 'repository'),
            ('controller_pull_request', 'pull_request'),
            ('controller_pull_request', 'commit'),
            ('head_ref', 'repository'),
            ('head_ref', 'pull_request'),
            ('head_ref', 'commit'),
        )
        for c in invalid_combinations:
            if getattr(args, c[0]) and getattr(args, c[1]):
                raise argparse.ArgumentError(None, "Cannot specify both --{} and --{}".format(*c))

        required_combinations = (
            ('repository', 'pull_request'),
        )
        for c in required_combinations:
            if (getattr(args, c[0]) is None) != (getattr(args, c[1]) is None):
                raise argparse.ArgumentError(None, "Both --{} and --{} are required if one is specified".format(*c))

        if args.controller_pull_request:
            # Handle later
            pass
        elif args.head_ref:
            m = cfg.exceptions_branch_regex.match(args.head_ref)
            if not m:
                raise argparse.ArgumentError(None, "Invalid head ref '{}', must be of the form '{}'".format(
                    args.head_ref, cfg.exceptions_branch_format))

            args.repository = m.group('repository')
            args.pull_request = int(m.group('pr_num'))
        elif not args.repository or not args.pull_request:
            raise argparse.ArgumentError(None, "Either --head-ref or --repository and --pull-request are required")

    gh = GithubApp(args.app_id, args.private_key)
    try:
        if args.controller_pull_request:
            # Get the controller repository
            ctrl_repo = gh.get_repo(args.controller_repository, lazy=True)

            # Get the pull request
            ctrl_pr = ctrl_repo.get_pull(args.controller_pull_request)

            # Get the repository and pull request number
            m = cfg.exceptions_branch_regex.match(ctrl_pr.head.ref)
            if not m:
                raise argparse.ArgumentError(None, "Pull request {} does not seem to be an exception request".format(
                    args.controller_pull_request))

            args.repository = m.group('repository')
            args.pull_request = int(m.group('pr_num'))

        if hasattr(args, 'repository'):
            args.repository_owner, args.repository_name = parse_repository(args.repository)

        # Now that we have the arguments, we can create the run object
        run = Run(gh, args, cfg=cfg)

        if args.operation == 'update':
            run.update(best_effort=args.best_effort)
        elif args.operation == 'cron':
            run.cron_update()
        elif args.operation == 'request':
            run.update(move_to_requested=True)
        else:
            # Should never happen
            raise RuntimeError("Invalid operation: {}".format(operation))
    finally:
        # Make sure we revoke the token when we are done using it
        gh.revoke()


if __name__ == '__main__':
    main()

