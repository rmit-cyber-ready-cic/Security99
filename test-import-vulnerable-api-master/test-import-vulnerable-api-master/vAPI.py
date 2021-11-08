"""
s API interacts with a user and token database.
The code is written to exemplify common API security vulnerabilities
1. No input validation
2. SQL queries are not parameterized
3. No real error handling
4. Errors that are handled give too much information
4. Tokens have an expiration date, but do not expire
5. Token string is generated with an md5 of the expire datetime string
6. Passwords are not hashed in the database
7. There is an *undocumented* GET that returns the user database
"""
from __future__ import print_function

import connexion
import sqlite3
import json
import hashlib
import time
import os
import re
import xml.etree.ElementTree as ET
import logging
import sys
import getopt
from lxml import etree


def get_root():
    '''
    Give default message for a GET on root directory.
    '''
    src_ip=connexion.request.environ.get('HTTP_X_FORWARDED_FOR') or connexion.request.environ.get('REMOTE_ADDR')
    response = {'response':
                {
                    'application': 'vAPI',
                    'status': 'running'
                }
                }
    logging.info("app=vAPI: src_ip=%s action=success signature=\"API status request\"" % src_ip)
    return response, 200


def get_token():
    '''
    User needs to get an auth token before actioning the database
    '''
    src_ip=connexion.request.environ.get('HTTP_X_FORWARDED_FOR') or connexion.request.environ.get('REMOTE_ADDR')
    content_type = connexion.request.headers.get('Content-type')
    if content_type == 'application/xml':
        try:
            # LXML is vulnerable to XXE, etree is vulnerable to Billion Laughs
            # So just have etree try to parse it just to watch it die
            ET.parse(connexion.request.body)
        except Exception:
            # But etree will throw an exception for XXE, so ignore that
            pass
        # force unsafe external entity parsing
        parser = etree.XMLParser(load_dtd=True, resolve_entities=True)
        data = etree.parse(connexion.request.body, parser)
        username = data.find('username').text
        password = data.find('password').text
    else:
        data = connexion.request.get_json() if connexion.request.is_json else {}
        username = data.get('username',"")
        password = data.get('password',"")
    conn = sqlite3.connect('vAPI.db')
    c = conn.cursor()
    # no data validation
    # no sql parameterization
    user_query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (
        username, password)
    c.execute(user_query)
    user = c.fetchone()
    response = {}
    if user:
        response['access'] = {}
        response['access']['user'] = {'id': user[0], 'name': user[1]}
        # make sure to get most recent token in database, because we arent
        # removing them...
        token_query = "SELECT * FROM tokens WHERE userid = '%s' ORDER BY expires DESC" % (user[0])
        c.execute(token_query)
        token_record = c.fetchone()
        if isinstance(token_record, tuple):
            if token_record[3] < int(time.time()):
                # token has expired. create new one that expires 5 minutes
                # after creation
                expire_stamp = int(time.time() + 300)
                expire_date = time.ctime(int(expire_stamp))
                token = hashlib.md5(expire_date.encode('utf-8')).hexdigest()
                # we'll parameterize this one because we need this serious
                # functionality
                c.execute(
                    'INSERT INTO tokens (token, userid, expires) VALUES (?, ?, ?)',
                    (token,
                     user[0],
                        expire_stamp))
                conn.commit()
                response['access']['token'] = {
                    'id': token, 'expires': expire_date}
                logging.info("app=vAPI:tokens src_ip=%s user=%s action=success signature=\"Request token: authentication succeeded, found expired token in db\"" % (src_ip, username))
                return response, 200
            else:
                # recent token hasn't expired. use same one.
                expire_date = time.ctime(int(token_record[3]))
                response['access']['token'] = {
                    'id': token_record[1], 'expires': expire_date}
                logging.info("app=vAPI:tokens src_ip=%s user=%s action=success signature=\"Request token: authentication succeeded, found recent token in db\"" % (src_ip, username))
                return response, 200
        else:
            # no token exists. create one that expires in 5 minutes
            expire_stamp = int(time.time() + 300)
            expire_date = time.ctime(int(expire_stamp))
            token = hashlib.md5(expire_date.encode('utf-8')).hexdigest()
            # we'll parameterize this one because we need this serious
            # functionality
            c.execute(
                'INSERT INTO tokens (token, userid, expires) VALUES (?, ?, ?)',
                (token,
                 user[0],
                    expire_stamp))
            conn.commit()
            response['access']['token'] = {'id': token, 'expires': expire_date}
            logging.info("app=vAPI:tokens src_ip=%s user=%s action=success signature=\"Request token: authentication succeeded, created new token in db\"" % (src_ip, username))
            return response, 200
    else:
        # let's do another look up so we can return helpful info for failure
        # cases
        c.execute("SELECT * FROM users WHERE username = '%s'" % username)
        user = c.fetchone()
        if user:
            response['error'] = {'message': 'password does not match'}
            logging.info("app=vAPI:tokens src_ip=%s user=%s action=failure signature=\"Request token: authentication failed, wrong password\"" % (src_ip, username))
        else:
            logging.info("app=vAPI:tokens src_ip=%s user=%s action=failure signature=\"Request token: authentication failed, user unknown\"" % (src_ip, username))
            response['error'] = {
                'message': 'username ' + username + ' not found'}
        return response, 401

def get_get_token():
    '''
    this is an undocumented request. EASTER EGG
    /tokens is only supposed to accept a POST! Are you checking the other verbs?
    '''
    conn = sqlite3.connect('vAPI.db')
    c = conn.cursor()
    query = "SELECT * FROM users"
    c.execute(query)
    users = c.fetchall()
    c.close()
    conn.close()
    return {'response': users}, 200


def get_user(user):
    '''
    Expects a user id to return that user's data.
    X-Auth-Token is also expected
    '''
    src_ip=connexion.request.environ.get('HTTP_X_FORWARDED_FOR') or connexion.request.environ.get('REMOTE_ADDR')
    token = connexion.request.headers.get('X-Auth-Token')
    try:
        conn = sqlite3.connect('vAPI.db')
        c = conn.cursor()
        user_query = "SELECT * FROM users WHERE id = '%s'" % (user)
        c.execute(user_query)
        user_record = c.fetchone()
        token_query = "SELECT * FROM tokens WHERE token = '%s'" % (str(token))
        c.execute(token_query)
        token_record = c.fetchone()
        c.close()
    except Exception:
        return {"error": "database error"}, 500
    response = {}
    # you'll notice we don't actually check the token expiration date
    if isinstance(token_record, tuple):
        if isinstance(user_record, tuple):
            if token_record[2] == user_record[0]:
                response['user'] = {}
                response['user']['id'] = user_record[0]
                response['user']['name'] = user_record[1]
                response['user']['password'] = user_record[2]
                logging.info("app=vAPI:user src_ip=%s user=%s action=success signature=\"Requesting user record: success for user record %s\"" % (src_ip, token_record[2], user))
                return response, 200
            else:
                response['error'] = {
                    'message': 'the token and user do not match!'}
                logging.info("app=vAPI:user src_ip=%s user=%s action=failure signature=\"Requesting user record: no permission to show user=%s\"" % (src_ip, token_record[2], user))
                return response, 403
        else:
            response['error'] = {'message': 'user id ' + user + ' not found'}
            logging.info("app=vAPI:user src_ip=%s user=%s action=failure signature=\"Requesting user record: failed for unknown user %s\"" % (src_ip, "", user))
            return response, 404
    else:
        response['error'] = {
            'message': 'token id ' + str(token) + ' not found'}
        logging.info("app=vAPI:user src_ip=%s user=%s action=failure \"Requesting user record: authentication failed for user %s\"" % (src_ip, "" , user))
        return response, 401

def create_user():
    src_ip=connexion.request.environ.get('HTTP_X_FORWARDED_FOR') or connexion.request.environ.get('REMOTE_ADDR')
    token = connexion.request.headers.get('X-Auth-Token')
    conn = sqlite3.connect('vAPI.db')
    c = conn.cursor()
    token_query = "SELECT * FROM tokens WHERE token = '%s' AND userid = 10" % (
        str(token))
    c.execute(token_query)
    token_record = c.fetchone()
    response = {}
    if isinstance(token_record, tuple):
        data = connexion.request.get_json() if connexion.request.is_json else {}
        name = data.get('username','')
        password = data.get('password','')
        # catastrophically bad regex
        match = "([a-z]+)*[0-9]"
        m = re.search(match, name)
        if m:
            user_query = "SELECT * FROM users WHERE username = '%s'" % (name)
            c.execute(user_query)
            user_record = c.fetchone()
            if isinstance(user_record, tuple):
                response['error'] = {
                    "message": "User %s already exists!" %
                    name}
                logging.info("app=vAPI:user src_ip=%s user=%s action=failure signature=\"Create new user: already existing user %s\"" % (src_ip, token_record[2], name))
                return response, 403
            else:
                c.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)", (name, password))
                conn.commit()
                response['user'] = {"username": name, "password": password}
                logging.info("app=vAPI:user src_ip=%s user=%s action=success signature=\"Create new user: %s\"" % (src_ip, token_record[2], name))
                return response, 200
        else:
            response['error'] = {
                "message": "username {0} invalid format, check documentation!".format(name)}
            logging.info("app=vAPI:user src_ip=%s user=%s action=failure signature=\"Create new user: invalid name %s\"" % (src_ip, token_record[2], name))
            return response, 403
    else:
        response['error'] = {"message": "must provide valid admin token"}
        logging.info("app=vAPI:user src_ip=%s action=failure signature=\"Create new user: authentication failed, invalid token\"" % src_ip)
        return response, 401

def display_uptime():
    return display_uptime_flag(False)

def display_uptime_flag(flag):
    src_ip=connexion.request.environ.get('HTTP_X_FORWARDED_FOR') or connexion.request.environ.get('REMOTE_ADDR')
    if flag:
        command = "uptime -" + flag
        logging.info("app=vAPI:uptime src_ip=%s action=success signature=\"Uptime request: flag=%s\"" % (src_ip, flag))
    else:
        command = "uptime" 
        logging.info("app=vAPI:uptime src_ip=%s action=success signature=\"Uptime request\"" % src_ip) 
    output = os.popen(command).read() 
    response = {'response':
        {
              'command': command,
              'output': output
        }}
    return json.dumps(response, sort_keys=True, indent=2), 200

def create_widget_reservation():
    src_ip=connexion.request.environ.get('HTTP_X_FORWARDED_FOR') or connexion.request.environ.get('REMOTE_ADDR')
    token = connexion.request.headers.get('X-Auth-Token')
    conn = sqlite3.connect('vAPI.db')
    c = conn.cursor()
    token_query = "SELECT * FROM tokens WHERE token = '%s'" % (
        str(token))
    c.execute(token_query)
    token_record = c.fetchone()
    response = {}
    data = connexion.request.get_json() if connexion.request.is_json else {}
    name = data.get('name',{})
    c.close()
    conn.close()
    if isinstance(token_record, tuple):
        # catastrophically bad regex
        match = "([a-z]+)*[0-9]"
        m = re.search(match, str(name))
        if m:
            response = {"message": "created reservation for widget %s" % name}
            logging.info("app=vAPI:widget src_ip=%s user=%s action=success signature=\"Create reservation: widget=%s\"" % (src_ip, token_record[2], name))
            return response, 200
        else:
            response['error'] = {"message": "illegal widget name"}
            logging.info("app=vAPI:widget src_ip=%s user=%s action=failure signature=\"Create reservation: illegal name widget=%s\"" % (src_ip, token_record[2], name))
            return response, 403
    else:
        response['error'] = {"message": "must provide valid token"}
        logging.info("app=vAPI:widget src_ip=%s action=failure signature=\"Create reservation: authentication failure widget=%s\"" % (src_ip, name))
        return response, 401

if __name__ == '__main__':
    logging.basicConfig(filename="vAPI.log",
                        filemode='a',
                        format='%(asctime)s.%(msecs)03d %(levelname)s %(message)s',
                        datefmt='%Y-%m-%dT%H:%M:%S',
                        level=logging.INFO)
    logging.info("Starting vAPI")
    logger = logging.getLogger('vAPI')
    try:
        opts,args = getopt.getopt(sys.argv[1:],"hp:")
    except getopt.GetoptError:
        print("vAPI.py -p <port>")
        sys.exit(2)
    myport=8081
    for opt, arg in opts:
        if opt == "-h":
            print("vAPI.py -p <port>")
            sys.exit(0)
        elif opt == "-p":
            myport = int(arg)
    app = connexion.FlaskApp(__name__, specification_dir='openapi/')
    app.add_api('vAPI.yaml', arguments={'title': 'Vulnerable API'})
    app.run(port=myport, debug=True)
