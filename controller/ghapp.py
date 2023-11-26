import github
import logging
from github import Github, GithubIntegration, Auth


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

