import datetime
import logging
import os
import re
import yaml

from const import CONFIG_DIR, SCHEDULES_DIR, TEMPLATES_DIR
from freeze_window import FreezeWindow
from repository_list import RepositoryList
from utils import force_list, has_pattern_matching


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
    def exceptions_repository(self):
        return self.controller['exceptions']['repository']

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
    def skip_check_merge_groups(self):
        return self.controller['status']['skip_check_merge_groups']

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
    def activating_window_pr_max_age_days(self):
        return self.controller['windows']['freeze_max_age_days']

    @property
    def deactivating_window_pr_max_age_days(self):
        return self.controller['windows']['thaw_max_age_days']

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
    def labels_thawed(self):
        return set(self.controller['labels']['thawed'])

    @property
    def labels_target_merged(self):
        return set(self.controller['labels']['target_merged'])

    @property
    def labels_target_merged_without_approval(self):
        return set(self.controller['labels']['target_merged_without_approval'])

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
        validate_bool = lambda v: isinstance(v, bool)
        validate_nonempty_list = lambda v: isinstance(v, list) and len(v) > 0

        def validate_repository_full_name(value):
            return isinstance(value, str) and '/' in value and not has_pattern_matching(value)

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
                'repository': {
                    '_validate': validate_repository_full_name,
                },
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
                'skip_check_merge_groups': {
                    '_validate': validate_bool,
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
                'freeze_max_age_days': {
                    '_validate': lambda v: isinstance(v, int) and v >= 0,
                },
                'thaw_max_age_days': {
                    '_validate': lambda v: isinstance(v, int) and v >= 0,
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
                'thawed': {
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
                return RepositoryList(contents, self._default_org)
        return RepositoryList(default_org=self._default_org)

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

    def find_active_freeze_window_for(self, repository, target_base_branch):
        now = datetime.datetime.now(datetime.timezone.utc)

        # Check if the repository is in the globally defined repositories
        global_repository = None

        # Find all files in the schedules directory, recursively
        for window in self.freeze_windows:
            if not window.applies_to(now):
                continue

            if global_repository is None:
                global_repository = self.global_repositories.matches_with_branch(
                    repository,
                    target_base_branch,
                )

            if not window.matches_with_branch(repository,
                                              target_base_branch,
                                              global_repository):
                continue

            return window.with_extra_approvers(self.global_approvers)

