import fnmatch
import os

from const import TEMPLATES_DIR


def matches(repository, patterns):
    return any(fnmatch.fnmatch(repository, pattern) for pattern in patterns)


def force_list(value):
    if isinstance(value, list) or isinstance(value, tuple) or isinstance(value, set):
        return value
    elif isinstance(value, str):
        return [value]
    else:
        return []


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

