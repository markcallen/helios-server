"""
NodeJS Authentication

"""

from django.http import *
from django.core.mail import send_mail
from django.conf import settings
from rauth import OAuth2Service

import httplib2,json

import sys, os, cgi, urllib, urllib2, re

from oauth2client.client import OAuth2WebServerFlow

# some parameters to indicate that status updating is not possible
STATUS_UPDATES = False

# display tweaks
LOGIN_MESSAGE = "Log in with my NodeJS Account"

def get_flow(redirect_url=None):
  print "get_flow"
  return OAuth2Service(
        client_id=settings.NODEJS_CLIENT_ID,
        client_secret=settings.NODEJS_CLIENT_SECRET,
        name=settings.NODEJS_APP_NAME,
        authorize_url='http://localhost:8888/dialog/authorize',
        access_token_url='http://localhost:8888/oauth/token',
        base_url='http://localhost:8888/')

def get_auth_url(request, redirect_url):
  print "get_auth_url", redirect_url
  flow = get_flow(redirect_url)

  request.session['nodejs-redirect-url'] = redirect_url

  params = {'scope': 'email',
            'response_type': 'code',
            'redirect_uri': redirect_url
           }
  return flow.get_authorize_url(**params)

def get_user_info_after_auth(request):
  print "get_user_info_after_auth"
  flow = get_flow(request.session['nodejs-redirect-url'])

  code = request.GET['code']
  data={'code': code, 'redirect_uri': request.session['nodejs-redirect-url'], 'grant_type':'authorization_code'}
  del request.session['nodejs-redirect-url']

  response = flow.get_raw_access_token(data=data)

  response = response.json()
  oauth2_session = flow.get_session(response['access_token'])
  user = oauth2_session.get('http://localhost:8888/api/account').json()

  email = user['email']
  name = user['firstname'] + " " + user['lastname']

  # watch out, response also contains email addresses, but not sure whether thsoe are verified or not
  # so for email address we will only look at the id_token
  
  return {'type' : 'nodejs', 'user_id': email, 'name': name , 'info': {'email': email}, 'token':{}}
    
def do_logout(user):
  print "do_logout"
  """
  logout of NodeJS
  """
  return None
  
def update_status(token, message):
  print "update_status"
  """
  simple update
  """
  pass

def send_message(user_id, name, user_info, subject, body):
  print "send_message"
  """
  send email to google users. user_id is the email for google.
  """
  send_mail(subject, body, settings.SERVER_EMAIL, ["%s <%s>" % (name, user_id)], fail_silently=False)
  
def check_constraint(constraint, user_info):
  print "check_constraint"
  """
  for eligibility
  """
  pass
