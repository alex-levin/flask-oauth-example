import json

from rauth import OAuth1Service, OAuth2Service
from flask import current_app, url_for, request, redirect, session
import requests

# https://rauth.readthedocs.io/en/latest/api/


class OAuthSignIn(object):
    providers = None

    def __init__(self, provider_name):
        self.provider_name = provider_name
        credentials = current_app.config['OAUTH_CREDENTIALS'][provider_name]
        self.consumer_id = credentials['id']
        self.consumer_secret = credentials['secret']

    def authorize(self):
        pass

    def callback(self):
        pass

    def get_callback_url(self):
        return url_for('oauth_callback', provider=self.provider_name,
                       _external=True)

    @classmethod
    def get_provider(self, provider_name):
        if self.providers is None:
            self.providers = {}
            for provider_class in self.__subclasses__():
                provider = provider_class()
                self.providers[provider.provider_name] = provider
        return self.providers[provider_name]


class FacebookSignIn(OAuthSignIn):
    def __init__(self):
        super(FacebookSignIn, self).__init__('facebook')
        self.service = OAuth2Service(
            name='facebook',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url='https://graph.facebook.com/oauth/authorize',
            access_token_url='https://graph.facebook.com/oauth/access_token',
            base_url='https://graph.facebook.com/'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            scope='email',
            response_type='code',
            redirect_uri=self.get_callback_url())
        )

    def callback(self):
        def decode_json(payload):
            return json.loads(payload.decode('utf-8'))

        if 'code' not in request.args:
            return None, None, None
        oauth_session = self.service.get_auth_session(
            data={'code': request.args['code'],
                  'grant_type': 'authorization_code',
                  'redirect_uri': self.get_callback_url()},
            decoder=decode_json
        )
        me = oauth_session.get('me?fields=id,email').json()
        return (
            'facebook$' + me['id'],
            me.get('email').split('@')[0],  # Facebook does not provide
                                            # username, so the email's user
                                            # is used instead
            me.get('email')
        )


class TwitterSignIn(OAuthSignIn):
    def __init__(self):
        super(TwitterSignIn, self).__init__('twitter')
        self.service = OAuth1Service(
            name='twitter',
            consumer_key=self.consumer_id,
            consumer_secret=self.consumer_secret,
            request_token_url='https://api.twitter.com/oauth/request_token',
            authorize_url='https://api.twitter.com/oauth/authorize',
            access_token_url='https://api.twitter.com/oauth/access_token',
            base_url='https://api.twitter.com/1.1/'
        )

    def authorize(self):
        request_token = self.service.get_request_token(
            params={'oauth_callback': self.get_callback_url()}
        )
        session['request_token'] = request_token
        return redirect(self.service.get_authorize_url(request_token[0]))

    def callback(self):
        request_token = session.pop('request_token')
        if 'oauth_verifier' not in request.args:
            return None, None, None
        oauth_session = self.service.get_auth_session(
            request_token[0],
            request_token[1],
            data={'oauth_verifier': request.args['oauth_verifier']}
        )
        me = oauth_session.get('account/verify_credentials.json').json()
        social_id = 'twitter$' + str(me.get('id'))
        username = me.get('screen_name')
        return social_id, username, None   # Twitter does not provide email


class GitHubSignIn(OAuthSignIn):
    def __init__(self):
        super(GitHubSignIn, self).__init__('github')
        self.service = OAuth2Service(
            name='github',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            # https://developer.github.com/apps/building-oauth-apps/authorizing-oauth-apps/
            authorize_url='https://github.com/login/oauth/authorize',
            access_token_url='https://github.com/login/oauth/access_token',
            base_url='https://api.github.com/'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            scope='user',
            response_type='code',
            redirect_uri=self.get_callback_url())
        )

    def callback(self):
        def decode_json(payload):
            return json.loads(payload.decode('utf-8'))

        if 'code' not in request.args:
            return None, None, None

        # Retrieve an access token
        # https://rauth.readthedocs.io/en/latest/api/
        # oauth_session = self.service.get_auth_session(
        oauth_session = self.service.get_raw_access_token(
            data={'code': request.args['code'],
                  'grant_type': 'authorization_code',
                  'redirect_uri': self.get_callback_url()}
        )
        # access_token=66ed1b082d2a46fff54ee917319489f151abbaa2&scope=user&token_type=bearer
        print(oauth_session.text)
        token = oauth_session.text.split('&')[0].split('=')[1]
        # 66ed1b082d2a46fff54ee917319489f151abbaa2
        print(token)
        # curl -s "https://api.github.com/users/alex-levin" -H "Authorization: token:66ed1b082d2a46fff54ee917319489f151abbaa2"
        r = requests.get('https://api.github.com/users/alex-levin', headers={'Authorization': f'token:$token'})
        '''
        b'{"login":"alex-levin","id":1595599,"node_id":"MDQ6VXNlcjE1OTU1OTk=",
        "avatar_url":"https://avatars2.githubusercontent.com/u/1595599?v=4",
        "gravatar_id":"","url":"https://api.github.com/users/alex-levin",
        "html_url":"https://github.com/alex-levin","followers_url":"https://api.github.com/users/alex-levin/followers",
        "following_url":"https://api.github.com/users/alex-levin/following{/other_user}",
        "gists_url":"https://api.github.com/users/alex-levin/gists{/gist_id}",
        "starred_url":"https://api.github.com/users/alex-levin/starred{/owner}{/repo}",
        "subscriptions_url":"https://api.github.com/users/alex-levin/subscriptions",
        "organizations_url":"https://api.github.com/users/alex-levin/orgs",
        "repos_url":"https://api.github.com/users/alex-levin/repos",
        "events_url":"https://api.github.com/users/alex-levin/events{/privacy}",
        "received_events_url":"https://api.github.com/users/alex-levin/received_events",
        "type":"User","site_admin":false,"name":"Alex Levin","company":null,"blog":"",
        "location":"Natick, MA","email":null,"hireable":null,"bio":null,"public_repos":202,
        "public_gists":24,"followers":0,"following":1,"created_at":"2012-04-01T14:30:11Z",
        "updated_at":"2020-04-21T11:13:02Z"}'
        '''
        print(r.content)
        # print('>>> I am here2')
        # me = oauth_session.get('me?fields=id,email').json()
        # # {'message': 'Not Found', 'documentation_url': 'https://developer.github.com/v3'}
        # print('MMM', me)

        # This returns tuple: id, email
        # return (
        #     'github$' + me['id'],
        #     me.get('email').split('@')[0],  # Facebook does not provide
        #                                     # username, so the email's user
        #                                     # is used instead
        #     me.get('email')
        # )
