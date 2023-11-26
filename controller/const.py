import os

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
GIT_DIR = os.path.join(CURRENT_DIR, '..')
CONFIG_DIR = os.path.join(GIT_DIR, 'configuration')
SCHEDULES_DIR = os.path.join(CONFIG_DIR, 'schedules')
TEMPLATES_DIR = os.path.join(CURRENT_DIR, 'templates')
