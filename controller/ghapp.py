import github
import logging
from contextlib import contextmanager
from github import Github, GithubIntegration, Auth


@contextmanager
def github_apps(ctrl_args, contents_args):
    if ctrl_args == contents_args:
        with github_app_auth(*ctrl_args) as gh:
            yield gh, gh
    else:
        with github_app_auth(*ctrl_args, context='controller') as gh_ctrl:
            with github_app_auth(*contents_args, context='contents') as gh_contents:
                yield gh_ctrl, gh_contents


@contextmanager
def github_app_auth(*args, **kwargs):
    gh = GithubApp(*args, **kwargs)
    try:
        yield gh
    finally:
        gh.revoke()


class GithubApp(object):
    def __init__(self, app_id, private_key, context=None):
        self.logger = logging.getLogger('github-app')
        self.logger.info('Creating GithubApp object{}'.format(' ({})'.format(context) if context else ''))
        self._context = context

        ghauth = Auth.AppAuth(app_id, private_key)
        ghi = GithubIntegration(auth=ghauth)
        installation = ghi.get_installations()[0]
        self.__gh = installation.get_github_for_installation()
        #TODO: add permissions when getting a token? we would need to select both repositories we need
        #  self.__access_token = ghi.get_access_token(installation.id)
        #  self.__gh = Github(self.__access_token.token)

    def revoke(self):
        self.logger.info('Revoking token{}'.format(' ({})'.format(self._context) if self._context else ''))
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

