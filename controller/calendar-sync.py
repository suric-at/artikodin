#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This script checks if a given calendar

import argparse
import datetime
import jinja2
import logging
import os
import re
import yaml

from google.auth.transport.requests import Request
from google.oauth2 import service_account
from googleapiclient.discovery import build

from approvers import Approver
from config_data import ConfigData
from const import CONFIG_DIR


class GoogleCalendarFreezeWindowEvents(object):
    _FREEZE_WINDOW_ID_REG = re.compile(r'^<!-- freeze_window:(.*?) -->')

    def __init__(self, credentials_path, freeze_windows, dry_run=False):
        self._logger = logging.getLogger(__name__)

        self._credentials_path = credentials_path
        self._freeze_windows = freeze_windows
        self._dry_run = dry_run

    def check(self):
        self.calendar_config

    @property
    def calendar_config(self):
        if not hasattr(self, '_calendar_config'):
            config_calendar_path = os.path.join(CONFIG_DIR, 'calendar.yaml')
            if not os.path.exists(config_calendar_path):
                raise RuntimeError("Calendar configuration file does not exist")

            with open(config_calendar_path, 'r') as f:
                config = yaml.safe_load(f)

                # Check the core of the configuration
                if not isinstance(config, dict):
                    raise RuntimeError("Calendar configuration file is not a dictionary")

                # Check the calendar id
                calendar_id = config.get('calendar_id')
                if not calendar_id:
                    raise RuntimeError("Calendar configuration file does not have a calendar ID")

                if not isinstance(calendar_id, str):
                    raise RuntimeError("Calendar configuration calendar ID is not a string")

                # Check the attendees list
                attendees = config.get('attendees')
                if not attendees:
                    raise RuntimeError("Calendar configuration file does not have any attendees")

                if not isinstance(attendees, list):
                    raise RuntimeError("Calendar configuration attendees is not a list")

                for attendee in attendees:
                    if not isinstance(attendee, str):
                        raise RuntimeError("Calendar attendee '{}' is not a string".format(attendee))

                    if '@' not in attendee:
                        raise RuntimeError("Calendar attendee '{}' is not an email address".format(attendee))

                # Check the description template
                description_template = config.get('description_template')
                if not description_template:
                    raise RuntimeError("Calendar configuration file does not have a description template")
                if not isinstance(description_template, str):
                    raise RuntimeError("Calendar configuration description template is not a string")

                try:
                    self._desc_template = jinja2.Environment().from_string(description_template)
                    self._desc_template.render(
                        freeze_details='something',
                        reviewers=[
                            Approver({
                                'handle': 'someone',
                                'reviewer': True,
                                'from': datetime.datetime.now(datetime.timezone.utc),
                                'to': datetime.datetime.now(datetime.timezone.utc),
                            }),
                        ],
                    )
                except KeyError as e:
                    raise RuntimeError("Calendar configuration description template is not valid: {}".format(e))

                self._calendar_config = config

        return self._calendar_config

    @property
    def calendar_id(self):
        return self.calendar_config['calendar_id']

    @property
    def calendar_attendees(self):
        return self.calendar_config['attendees']

    def event_description(self, freeze_window):
        desc = self._desc_template.render(
            freeze_details=" for {}".format(freeze_window.reason)
                           if freeze_window.reason else "",
            reviewers=freeze_window.all_reviewers(),
        )

        return "<!-- freeze_window:{} -->{}".format(
            freeze_window.id,
            desc,
        )

    @property
    def credentials(self):
        if not hasattr(self, '_credentials'):
            core_credentials = service_account.Credentials.from_service_account_file(
                self._credentials_path,
                scopes=['https://www.googleapis.com/auth/calendar'],
            )
            credentials = core_credentials.with_subject(self.calendar_id)

            self._credentials = credentials

        # If the credentials are expired, refresh them
        if self._credentials.expired:
            self._credentials.refresh(Request())

        return self._credentials

    @property
    def service(self):
        if not hasattr(self, '_service'):
            self._service = build('calendar', 'v3', credentials=self.credentials)

        return self._service

    def existing_freeze_events(self, from_date=None):
        events = []
        get_more_events = True
        next_page_token = None

        while get_more_events:
            events_result = self.service.events().list(
                calendarId=self.calendar_id,
                maxResults=250,
                singleEvents=True,
                orderBy='startTime',
                eventTypes='default',
                q='Freeze:',
                pageToken=next_page_token,
                timeMin=(
                    from_date.isoformat() if from_date
                    else datetime.datetime(
                        datetime.datetime.now().year, 1, 1,
                        tzinfo=datetime.timezone.utc).isoformat()
                ),
            ).execute()

            # Get the events returned
            events.extend(events_result.get('items', []))

            # Handle pagination if needed
            next_page_token = events_result.get('nextPageToken')
            if not next_page_token:
                get_more_events = False

        if not events:
            return {}

        freeze_windows = {}
        for event in events:
            m = self._FREEZE_WINDOW_ID_REG.search(event['description'])
            if not m:
                continue

            freeze_window_id = m.group(1)

            if freeze_window_id in freeze_windows:
                self._logger.warning(f"Duplicate freeze window ID in events: {freeze_window_id}")

            freeze_windows[freeze_window_id] = event

        return freeze_windows

    def sync(self):
        # Select among the freeze windows the ones that are yet to happen
        now = datetime.datetime.now(datetime.timezone.utc)
        freeze_windows = [
            freeze_window
            for freeze_window in self._freeze_windows
            if freeze_window.current_or_future(now)
        ]
        freeze_windows.sort(key=lambda fw: (fw.from_date, fw.to_date))

        if not freeze_windows:
            self._logger.info("No freeze windows to sync")
            return

        # Get the freeze window with the earliest start date
        earliest_date = min(
            freeze_windows,
            key=lambda fw: fw.from_date
        ).from_date

        # Use now if it's earlier than the earliest freeze window
        earliest_date = min(
            earliest_date,
            now,
        )

        self._logger.info(f"Syncing freeze windows starting from {earliest_date.isoformat()}")

        # Get all the existing events matching freeze windows
        existing_freeze_events = self.existing_freeze_events(from_date=earliest_date)

        # Go over the freeze windows, and either create or update the
        # corresponding event if needed
        unhandled_freeze_windows = set(existing_freeze_events.keys())
        for freeze_window in freeze_windows:
            unhandled_freeze_windows.discard(freeze_window.id)

            # Get the existing event if any
            existing_freeze_event = existing_freeze_events.get(freeze_window.id)

            # If there is no existing event, create one
            if not existing_freeze_event:
                self._logger.info(f"Creating freeze window event: {freeze_window.id}")
                self._create_freeze_window_event(freeze_window)
                continue

            # If the existing event is outdated, update it
            outdated = self._is_freeze_window_event_outdated(freeze_window, existing_freeze_event)
            if outdated:
                self._logger.info(f"Updating freeze window event: {freeze_window.id}")
                self._update_freeze_window_event(freeze_window, existing_freeze_event, send_updates=outdated[1])
                continue

            self._logger.info(f"Freeze window event already up to date: {freeze_window.id}")

        # Delete any event that is not in the freeze windows anymore
        for freeze_window_id in unhandled_freeze_windows:
            self._logger.info(f"Deleting freeze window event: {freeze_window_id}")
            if self._dry_run:
                self._logger.info(f"Would delete event: {existing_freeze_events[freeze_window_id]}")
                continue

            self.service.events().delete(
                calendarId=self.calendar_id,
                eventId=existing_freeze_events[freeze_window_id]['id'],
                sendUpdates='all',
            ).execute()

    def _get_freeze_window_event_data(self, freeze_window):
        return {
            'summary': 'Freeze: {}'.format(
                freeze_window.reason if freeze_window.reason
                else freeze_window.id),
            'location': 'Remote',
            'description': self.event_description(freeze_window),
            'start': {
                'dateTime': freeze_window.from_date.isoformat(),
            },
            'end': {
                'dateTime': freeze_window.to_date.isoformat(),
            },
            'attendees': [
                {'email': email}
                for email in self.calendar_attendees
            ],
            'reminders': {
                'useDefault': False,
            },
        }

    def _create_freeze_window_event(self, freeze_window):
        event_data = self._get_freeze_window_event_data(freeze_window)

        if self._dry_run:
            self._logger.info(f"Would create event: {event_data}")
            return

        event = self.service.events().insert(
            calendarId=self.calendar_id,
            body=event_data,
            sendUpdates='all',
        ).execute()

        self._logger.info(f"Event created: {event.get('htmlLink')}")

    def _is_freeze_window_event_outdated(self, freeze_window, existing_freeze_event):
        event_data = self._get_freeze_window_event_data(freeze_window)

        if event_data['summary'] != existing_freeze_event['summary']:
            self._logger.info(f"Event summary changed: {existing_freeze_event['summary']} -> {event_data['summary']}")
            return (True, False)

        if event_data['location'] != existing_freeze_event['location']:
            self._logger.info(f"Event location changed: {existing_freeze_event['location']} -> {event_data['location']}")
            return (True, False)

        if event_data['description'] != existing_freeze_event['description']:
            self._logger.info(f"Event description changed: {existing_freeze_event['description']} -> {event_data['description']}")
            return (True, False)

        existing_start_datetime = datetime.datetime.fromisoformat(existing_freeze_event['start']['dateTime'])
        expected_start_datetime = datetime.datetime.fromisoformat(event_data['start']['dateTime'])
        if existing_start_datetime != expected_start_datetime:
            self._logger.info(f"Event start changed: {existing_start_datetime} -> {expected_start_datetime}")
            return (True, True)

        existing_end_datetime = datetime.datetime.fromisoformat(existing_freeze_event['end']['dateTime'])
        expected_end_datetime = datetime.datetime.fromisoformat(event_data['end']['dateTime'])
        if existing_end_datetime != expected_end_datetime:
            self._logger.info(f"Event end changed: {existing_end_datetime} -> {expected_end_datetime}")
            return (True, True)

        # Check all expected attendees are there, we're fine if there are more
        expected_attendees = set(a['email'] for a in event_data['attendees'])
        existing_attendees = set(a['email'] for a in existing_freeze_event['attendees'])
        if len(expected_attendees - existing_attendees) > 0:
            self._logger.info(f"Event attendees changed: {existing_attendees} -> {expected_attendees}")
            return (True, True)

        return False

    def _update_freeze_window_event(self, freeze_window, existing_freeze_event, send_updates):
        event_data = self._get_freeze_window_event_data(freeze_window)

        new_event_data = existing_freeze_event.copy()

        # We can replace directly all values, except for the attendees, where
        # we want just to add the missing ones, but not to touch the existing
        # ones, so we don't remove responses from people that already responded
        for k, v in event_data.items():
            if k == 'attendees':
                expected_attendees = set(a['email'] for a in event_data['attendees'])
                existing_attendees = set(a['email'] for a in existing_freeze_event['attendees'])
                missing_attendees = expected_attendees - existing_attendees

                if missing_attendees:
                    new_event_data['attendees'].extend([
                        {'email': email}
                        for email in missing_attendees
                    ])
            else:
                new_event_data[k] = v

        if self._dry_run:
            self._logger.info(f"Would update event: {new_event_data}")
            return

        event = self.service.events().update(
            calendarId=self.calendar_id,
            eventId=new_event_data['id'],
            body=new_event_data,
            sendUpdates='all' if send_updates else 'none',
        ).execute()

        self._logger.info(f"Event updated: {event.get('htmlLink')}")


def validate_file_exists_and_readable(path):
    try:
        with open(path, 'r'):
            pass
    except IOError:
        raise argparse.ArgumentTypeError(f"File '{path}' does not exist or is not readable")

    return path


def main():
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(
        description='Update a calendar with freeze windows',
    )

    parser.add_argument(
        "--credentials-path",
        required=True,
        type=validate_file_exists_and_readable,
        help="Path to the credentials JSON file",
    )

    parser.add_argument(
        "--dry-run",
        action='store_true',
        help="Do not actually update the calendar",
    )

    args = parser.parse_args()

    # Check the configuration
    cfg = ConfigData(default_org='not_important')
    cfg.check()

    # Instantiate the calendar handler object
    calendar_handler = GoogleCalendarFreezeWindowEvents(
        credentials_path=args.credentials_path,
        freeze_windows=cfg.freeze_windows,
        dry_run=args.dry_run,
    )

    # Check the calendar handler configuration
    calendar_handler.check()

    # Sync the calendar
    calendar_handler.sync()


if __name__ == '__main__':
    main()
