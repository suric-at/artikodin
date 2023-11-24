#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This script checks if we are currently in a freeze window,
# that applies for the requested repository. If so, it will
# exit with a non-zero exit code and print parameters that
# can be used to inform the user about the freeze.

import argparse
import datetime
import fnmatch
import json
import os
import re
import sys
import yaml

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
GIT_DIR = os.path.join(CURRENT_DIR, '..', '..', '..')
CONFIG_DIR = os.path.join(GIT_DIR, 'configuration')
SCHEDULES_DIR = os.path.join(CONFIG_DIR, 'schedules')


def matches(repository, patterns):
    return any(fnmatch.fnmatch(repository, pattern) for pattern in patterns)


#  def parse_iso8601_with_timezone(iso_str):
    #  # Split the string into the datetime part and the timezone part
    #  datetime_part, tz_part = iso_str.rsplit(' ', 1)

    #  # Parse the datetime part
    #  dt = datetime.datetime.fromisoformat(datetime_part)

    #  # Parse the timezone offset
    #  if tz_part == 'Z':
        #  tz_offset = datetime.timezone.utc
    #  else:
        #  sign = 1 if tz_part[0] == '+' else -1
        #  hours, minutes = map(int, tz_part[1:].split(':'))
        #  tz_offset = datetime.timezone(datetime.timedelta(
            #  hours=sign * hours,
            #  minutes=sign * minutes,
        #  ))

    #  # Combine the datetime and timezone offset
    #  dt_with_tz = dt.replace(tzinfo=tz_offset)
    #  return dt_with_tz


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


def find_schedule_for(repository):
    now = datetime.datetime.now(datetime.timezone.utc)

    # Check if the repository is in the globally defined repositories
    global_repository = False
    with open(os.path.join(CONFIG_DIR, 'repositories.yaml'), 'r') as f:
        repositories = yaml.safe_load(f)
        global_repository = matches(repository, repositories)

    # Global approvers
    global_approvers = []
    with open(os.path.join(CONFIG_DIR, 'approvers.yaml'), 'r') as f:
        global_approvers = force_list(yaml.safe_load(f))

    # Find all files in the schedules directory, recursively
    for root, dirs, files in os.walk(SCHEDULES_DIR):
        # Load the file as YAML
        for file in files:
            if not file.endswith('.yaml'):
                continue

            with open(os.path.join(root, file), 'r') as f:
                schedule = yaml.safe_load(f)

                # Skip if there is no from or no to
                if 'from' not in schedule or 'to' not in schedule:
                    continue

                # Check first if the repository matches with the schedule
                only = force_list(schedule.get('only'))
                include = force_list(schedule.get('include'))
                exclude = force_list(schedule.get('exclude'))

                repo_matches = matches(repository, only) or \
                    matches(repository, include) or \
                    (global_repository and not only and not matches(repository, exclude))

                if not repo_matches:
                    continue

                # Check if now is in the window
                if schedule['from'] <= now <= schedule['to']:
                    all_approvers = (
                        clean_approvers(force_list(schedule.get('approvers'))) +
                        clean_approvers(global_approvers))

                    approvers = list({
                        approver['handle']: approver
                        for approver in all_approvers
                    }.values())

                    return {
                        'reason': schedule.get('reason'),
                        'from': schedule['from'],
                        'to': schedule['to'],
                        'approvers': approvers,
                    }


def main():
    parser = argparse.ArgumentParser(
        description='Check if we are in a freeze window.',
    )

    parser.add_argument(
        '--repository',
        required=True,
        help='The repository to check.',
    )

    args = parser.parse_args()

    schedule = find_schedule_for(args.repository)
    if schedule:
        print('FREEZE=true')
        print('FREEZE_REASON={}'.format(schedule.get('reason') or ''))
        print('FREEZE_FROM={}'.format(schedule['from'].isoformat()))
        print('FREEZE_TO={}'.format(schedule['to'].isoformat()))
        print('FREEZE_APPROVERS={}'.format(json.dumps(
            [approver['handle'] for approver in schedule['approvers']])))
        print('FREEZE_REVIEWERS={}'.format(json.dumps(
            [approver['handle'] for approver in schedule['approvers']
             if approver.get('reviewer')])))
    else:
        print('FREEZE=false')


if __name__ == '__main__':
    main()

