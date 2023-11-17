import json
import logging

from flask import Flask, g
from flask_oidc import OpenIDConnect
import requests

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

app.config['OIDC_CLIENT_SECRETS']            = 'client_secrets.json'
app.config['OIDC_SCOPES']                    = ['openid', 'email', 'profile']
app.config['SECRET_KEY']                     = 'Kkjk0GDnISFdurV6PdPf3XvckDDs4hPX'
app.config['OIDC_COOKIE_SECURE']             =  False
app.config['OIDC_CALLBACK_ROUTE']            = '/'
app.config['OIDC_OPENID_REALM']              = 'master'
app.config['OIDC_INTROSPECTION_AUTH_METHOD'] = 'client_secret_post'
app.config['OVERWRITE_REDIRECT_URI']         = 'http://localhost:4040/'
app.config['OIDC_TOKEN_TYPE_HINT']           = 'access_token'

oidc = OpenIDConnect(app)

@app.route('/api', methods=['POST'])
@oidc.accept_token(require_token=True)
def hello_api():
    """OAuth 2.0 protected API endpoint accessible via AccessToken"""
    print("hello from api method")  # This will be printed only if valid token
    return json.dumps({'hello': 'Welcome %s' % g.oidc_token_info['preferred_username'] })


if __name__ == '__main__':
    app.run(host='0.0.0.0',port=4050,debug=False)
