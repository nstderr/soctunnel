#!/usr/bin/python3


import socket
import requests
import os
import sys
import random
import time
import string
import praw
import argparse
import logging
import base64
import signal
from urllib.parse import urlparse
from urllib.parse import parse_qs
from bs4 import BeautifulSoup as bs

logger = logging.getLogger(__name__)


class Tunnel:

    """Create a connection from a local socket to site"""

    def __init__(self, host='0.0.0.0', port=random.randint(49152,65535),
            site='Reddit', smode='client', lmode='listen', delete=True):
        '''Create a new connection at host:port'''

        logger.debug(f'host:{host}, port:{port}')
        logger.debug(f'site:{site}, smode:{smode}')
        logger.debug(f'local mode:{lmode}')

        print(f'[*] Local socket will be on: {host}:{port}')
        self.host = host
        self.port = port
        self.smode = smode
        self.site = site
        self.delete = delete
        self.tunID = ''.join(random.choices(string.hexdigits, k = 8))
        logger.info(f'ClientID: {self.tunID}')
        print('Initializing site...')
        self.sitetun = self.initsite()
        print('Site initialized')
        print('Creating local connection to program')
        self.sock = self.createsocket(lmode)

    def createsocket(self, mode):
        '''Creates a new local socket or connects to a local socket that a program
           is already running on. Create socket is the default. pass -a to attach
           to a listening program.
        '''
        if mode == 'listen':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((self.host, self.port))
            s.listen(5)
            print('Local socket created')
            print('Waiting for connection...')
            sock, addr = s.accept()
            sock.setblocking(0)
        elif mode == 'attach':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print('Local socket created')
            try:
                s.connect((self.host, self.port))
                s.setblocking(0)
                sock = s
            except:
                print(f'[!] NO PROGRAM LISTENING ON PORT: {self.port}')
                sys.exit()

        print('[*] Program connected')
        return sock
    
    def initsite(self):
        '''Set up site - initialize user accounts and connect to other side. Mode
           determines if this side will send Syn msg or listen for other side. 
           Default is to send msg, pass -l to listen. One side needs to listen
        '''
        if self.site=='Reddit':
            return Reddit(self.tunID, self.smode, self.delete)
        else:
            logger.critical('Site not supported')
            sys.exit()

    def close(self,signal=None,frame=None,last=False):
        '''Close and tell partner to close. Sends 'CLOSE' msg to site'''
        print('Closing down')
        if not last:
            self.sitetun.close()
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        sys.exit()


    def getfrom_sock(self, sizelimit):
        '''Gets data from local socket and the program it's connected to'''
        datacomplete=False
        data = b''
        while len(data) < sizelimit: # each send is limited to 1 social media msg
            try:
                chunk = self.sock.recv(2048)
                if chunk == b'':
                    self.close()
            except BlockingIOError:
                datacomplete=True 
                break
            data += chunk
        return data, datacomplete

    def sendto_sock(self,data):
        '''Sends data to local socket and program connected to it.'''

        if type(data) != bytes:
            data = data.encode()
        self.sock.sendall(data)
    
    def run(self):
        while True:
            msgnum = 0 # msgs sent for this transfer
            while True:
                data = None
                data, datacomplete = self.getfrom_sock(self.sitetun.sizelimit)
                if data:
                    encdata = base64.b64encode(data)
                    if (msgnum % self.sitetun.sendlimit) == 0: # pause every sendlimit number of msgs
                        logger.debug('Sleeping to allow catchup')
                        time.sleep(5)
                    self.sitetun.senddata(data=encdata)
                    msgnum += 1
                if datacomplete == True:
                    break
    
            data = None
            data = self.sitetun.getdata()
            if data == 'CLOSE':
                self.close(last=True)
            logger.debug(f'Encoded Data from site: {data}')
            if data:
                assert type(data) == list
                for d in data:
                    decdata = base64.b64decode(d)
                    self.sendto_sock(decdata)
    

class Reddit:
    '''Class for site:reddit. Standard class uses separate accounts with separate
       API keys - Reddit calls this a script type app. 
    '''
    
    def __init__(self,tunid='tuntest000', mode = 'client', delete=True):

        logger.debug('Setting up Reddit instance')

        self.delete = False # reddit spam filter blocks accounts that get their msgs repeatedly deleted
        self.msglimit = 50 # number of msgs limit - for getdata and senddata, should be more than sendlimit
        self.sendlimit = 20 # applies to large data transfers. Number of msgs to send before pausing to allow receiver to catch up
        self.userlist = self.initusers() # build user list and reddit instances
        self.curuser = random.randint(0,len(self.userlist)-1) # start with random user 
        self.sizelimit = 25000 # per message limit
        self.tunID = tunid # clientID for tun instance
        self.seqnum = 0 # sequence number for sending traffic
        self.pseqnum = 0 # sequence number for received traffic
        self.databuffer = {} # store data that arrives out of sequence

        logger.debug(f'tunid: {tunid}, mode: {mode}')
        logger.info (f'username list: {[obj.name for obj in self.userlist]}, \
                current user: {self.curuser},  sizelimit: {self.sizelimit}')


        logger.debug('Done making reddit instance')
        logger.info('Connecting with otherside...')

        self.partnerID = self.create_tunnel(mode)

        logger.info('Connected.')
        logger.info(f'partnerid is: {self.partnerID}')


    class user:
        '''User class - name, reddit instance, subreddit instance'''
        def __init__(self, username, uagent, password,clientID,secret):

            logger.debug(f'Building user: {username}')
            state = str(random.randint(0,10000000))
            scope = 'identity read modposts submit'
            redir = 'http://127.0.0.1:1' # doesn't need to exist
            logger.debug(f'State: {state}; scope: {scope}; redir:{redir}')

            self.name = username

            self.prawR = praw.Reddit(
                    client_id = clientID,
                    client_secret = secret,
                    user_agent = uagent,
                    redirect_uri=redir) 

            logger.debug('Built prawR instance')
            
            authurl = self.prawR.auth.url(scope.split(' '),
                    state,'permanent')

            logger.debug(f'Auth url: {authurl}')

            logger.debug(f'User signing in and authorizing, getting code')
            code = self.getcode(username,password,authurl,clientID,secret,state,
                    scope,redir,uagent)
            logger.debug(f'User code: {code}')

            self.prawR.auth.authorize(code)
            logger.debug(f'User authorization finished')
            self.prawR.validate_on_submit=True
            # MOVE TO HIGHER CLASS
            self.subreddit = self.prawR.subreddit(os.environ['ST_subreddit'])

        def getcode(self,username,password, authurl, clientID, secret, state, 
                scope, redir, uagent):

            with requests.Session() as s:
                headers = {'User-Agent':uagent}
                logger.debug('Initial get request to authurl')
                res = s.get(authurl,headers=headers)
                try:
                    res.raise_for_status()
                except Exception as e:
                    logger.critical(f'Error when requesting {authurl}\n{e}')
                    sys.exit()
                soup = bs(res.content,'lxml')
                token = None
                token = soup.find(attrs={'name':'csrf_token'})['value']
                logger.debug('Got csrf for login')
                assert token is not None

                headers['Referer'] = res.url

                loginurl = 'https://www.reddit.com/login'
                
                # post data for login
                postdata = {
                        'csrf_token':token,
                        'otp':'',
                        'password':password,
                        'username':username,
                        'dest':authurl}

                logger.debug(f'Logging in. Headers:\n{headers}\nPost data:\n{postdata}')

                res = s.post(loginurl,headers=headers,data=postdata)
                logger.debug(f'Logged in')
                logger.debug('Get request to authurl')
                res = s.get(authurl, headers=headers)
                soup = bs(res.content,'lxml')
                token = None
                token = soup.find(attrs={'name':'uh'})['value']
                logger.debug(f'Got csrf "uh" for auth page: {token}')
                assert token is not None

                postdata = {
                        'client_id':clientID,
                        'redirect_uri': redir,
                        'scope': scope,
                        'state': state,
                        'response_type': 'code',
                        'duration':'permanent',
                        'uh': token,
                        'authorize': 'Allow'}

                del headers['Referer']

                url = urlparse(authurl)
                url = f'{url[0]}://{url[1]}{url[2]}'
                logger.debug('Sending post to authorize and get code')
                logger.debug(f'Url:{url}')
                logger.debug(f'Headers:\n{headers}')
                logger.debug(f'Post data:\n{postdata}')

                res = s.post(f'{url}',data=postdata,headers=headers,
                        allow_redirects=False)
                try:
                    res.raise_for_status()
                except Exception as e:
                    logger.critical(f'{e}')
                    sys.exit()
                logger.debug(f'\n{res.headers}\n')

            logger.debug(f'Getting Location url: {res.headers["Location"]}')
            query = parse_qs(urlparse(res.headers['Location']).query)
            logger.debug(f'Query params: {query}')
            assert f'{query["state"][0]}' == f'{state}'
            logger.debug(f'Got code: {query["code"]}')
            return query['code']


    def initusers(self):
        '''Get users from environment variables and build user objects. If ST_username 
           exists in environment assume only one account to be used. If username doesn't
           exist, assume usernameX exists, where X is an integer starting at 1 and 
           incrementing by 1 for every new user. Run for loop until X doesn't exist. 
        '''

        userlist = []
        clientID = os.environ['ST_clientID']
        logger.debug(f'ClientID set: {clientID}')
        secret = os.environ['ST_secret']
        logger.debug(f'Secret: {secret}')
        try:
            logger.debug('Only one user')
            username = os.environ['ST_username']
            uagent = f'Python: soctunnel:v1 (by u/{username})'
            password = os.environ['ST_password']
            userlist.append(self.user(username,uagent,password,clientID,secret))

        except:
            logger.debug('Multiple users selected')
            i = 1
            while True:
                try:
                    username = os.environ[f'ST_username{i}']
                    password = os.environ[f'ST_password{i}']
                    uagent = f'Python: soctunnel:v1 (by u/{username})'
                    userlist.append(self.user(username,uagent,password,clientID,secret))
                except KeyError as e:
                    break
                i += 1

        logger.debug(f'Userlist: {userlist}')
        if len(userlist) == 0:
            logger.critical('[!] NO USERS IN ENVIRONMENT VARIABLES!')
            sys.exit()
        return userlist


    def create_tunnel(self, mode):

        '''connect through site. If mode=listen, listen for S from other side (server).
           If mode=client, send S (client). Server connects to first S received. 
           Future feature will include ability to handle multiple clients for a 
           one-to-many connection mode- for sending commands to many clients.
           Default mode is client. Pass -l to listen and act as server
        '''

        partner = None
        if mode == 'client':
            timestamp = time.time()
            logger.debug(f'Client timestamp: {timestamp}')
            self.seqnum = 0
            logger.info('Client sending sync')
            self.senddata('S', f'{timestamp}') 
        elif mode == 'listen':
            timestart = time.time()
            logger.debug(f'Listener timestart: {timestart}')
            self.seqnum = 0

        while True:
            logger.info('Getting all messages')

            time.sleep(1) # increase rate limit for create_tunneling

            # move to next user
            self.curuser=self.curuser+1 if self.curuser + 1 < len(self.userlist) else 0
            logger.info(f'Using {self.userlist[self.curuser].name} to create_tunnel')

            for item in self.userlist[self.curuser].subreddit.new(limit=self.msglimit):
                # throw away anything from any other user not in list
                # msg needs to be in proper format
                # ignore message from this instance.

                if item.author not in [obj.name for obj in self.userlist]:
                    continue
                try:
                   ID, flag, seq = item.title.split(':')
                   seq = int(seq)
                except:
                    continue
                if ID == self.tunID:
                    continue
                # ***once handshake starts, ignore msgs from other clients
                elif partner and ID != partner:
                    continue
    
                if mode == 'client' and not partner:
                    if flag == 'SA' and item.selftext == self.tunID:
                        self.pseqnum = seq
                        partner = ID
                        logger.info(f'SYN/ACK flag received from partner:{ID}')
                        logger.debug(f'Partner Seq set to: {self.pseqnum}')
                        logger.info('Sending ACK')
                        self.senddata('A', f'{partner}')
                        item.mod.remove()
                        return partner
                elif mode == 'listen':
                    # listener needs to start before syn sent by client 
                    # this ensures old syn msgs are not used, even if
                    # they weren't deleted

                    if not partner and flag == 'S' and (float(item.selftext) > timestart):
                        partner = ID
                        self.pseqnum = seq
                        logger.info(f'Found SYN from partner: {ID}')
                        logger.debug(f'Partner Seq set to: {self.pseqnum}')
                        logger.info('Sending SYN/ACK')
                        self.senddata('SA', f'{partner}')
                        timestamp = time.time()
                        logger.debug(f'SYN/ACK timestamp: {timestamp}')
                        item.mod.remove()
                        break
                    elif partner and flag == 'CRST' and ID == partner:
                        logger.info('CRST received from client')
                        partner = None
                        timestamp = None
                        self.pseqnum = 0
                        self.seqnum = 0
                        logger.debug(f'Partner seq number reset: {self.pseqnum}')
                        item.mod.remove()
                    elif partner and flag == 'A' and item.selftext == self.tunID:
                        logger.info('ACK received from Client')
                        self.pseqnum = seq
                        logger.debug(f'Partner Seq set to: {self.pseqnum}')
                        item.mod.remove()
                        return partner

            # handle timeouts
            # if A from client takes to long, server sends SRST
            # if SA from server takes to long, client sends CRST and resends S

            # SRST handled by function getdata() - if server sends SRST due to timeout
            # it means client is dead or client thinks it's sent A but didn't
            # if client is dead, doesn't matter. If client thinks it's sent A,
            # it has moved on and thinks it's registered. Needs to reregister.
            # reregister called from getdata
            # CRST handled above. If client sends CRST due to timeout it means server 
            # is dead, server didn't get S from client, or server thinks it sent SA 
            # but didn't. If dead, doesn't matter. If didn't get S, client will resend S.
            # if it thinks it sent SA but didn't. Server needs to restart.
            
            if mode == 'listen' and partner and (time.time() - timestamp) > 60:
                logger.debug(f' TIme difference: {(time.time() - timestamp)}')
                logger.info(f'Timeout, SRST sent to {partner}')

                self.senddata('SRST', f'{partner}')
                partner = None
                timestamp = None
                self.seqnum = 0
                self.pseqnum = 0

            elif mode == 'client' and (time.time() - timestamp) > 20:
                logger.debug(f' TIme difference: {(time.time() - timestamp)}')
                logger.info(f'Timeout, CRST sent to {partner}')

                self.senddata('CRST',f'server didnt respond')
                timestamp = time.time()
                self.seqnum = 0
                self.pseqnum = 0
                self.senddata('S', f'{timestamp}')

                logger.info('Sent new SYN')
                logger.debug(f'TImestamp: {timestamp}')


    def close(self):
        '''Close site connection by sending 'CLOSE' msg.
           For now both sides close. Future one-to-many mode will have different
           options.
        '''
        self.senddata(flag='CLOSE')

    def senddata(self, flag='', data=''):
        '''Send data to site'''
        logger.debug(f'Sending data:\n{data}\n')
        logger.debug(f'Total message length: {len(data)}')

        logger.debug(f'Data split:\n{data}')

        
        try:
            logger.debug('Data sent:')
            logger.debug(f'Subject: {self.tunID}:{flag}:{self.seqnum}')
            logger.debug(f'Body: {data}')

            logger.debug(f'Sending with user: {self.userlist[self.curuser].name}')

            self.curuser=self.curuser+1 if self.curuser+1 < len(self.userlist) else 0

            self.userlist[self.curuser].subreddit.submit(
                    title=f'{self.tunID}:{flag}:{self.seqnum}', 
                    selftext=data)

            self.seqnum += 1

            logger.debug(f'Next sequence number: {self.seqnum}')

        except Exception as e:
            print(e)
                

    def getdata(self):
        '''Get data from site'''
        start = self.pseqnum
        data = []

        logger.debug('Getting Data from Reddit')
        logger.debug(f'Partner starting sequence number: {start}')

        
        self.curuser = self.curuser + 1 if self.curuser + 1 < len(self.userlist) else 0

        logger.debug(f'Getting data with {self.userlist[self.curuser].name}')


        # get all messages up to msglimit
        for item in self.userlist[self.curuser].subreddit.new(limit=self.msglimit):

            if item.author not in [obj.name for obj in self.userlist]:
                # approved users only
                continue
            try:
                # unpack subject line (message header)
               ID, flag, seq = item.title.split(':')
               seq = int(seq)
            except:
                continue
            if ID == self.tunID:
                continue
            elif ID != self.partnerID:
                continue

            logger.debug(f'Message partner ID: {ID}')
            if flag == 'CLOSE':
                print('[*]Partner Closed Connection!')
                item.mod.remove()
                return 'CLOSE'

            if flag == 'SRST':
                logger.info('Got SRST from server.')
                self.pseqnum = 0
                logger.debug(f'Sequence Number reset: {self.pseqnum}')
                logger.info('Re-registering with partner.')
                item.mod.remove()
                self.create_tunnel()
                return
    
            # only get new msgs
            logger.debug(f'Current Message seq: {seq}')
            logger.debug(f'Highest seq from last time: {start}')

            # check if msg is newer than last recorded and if msg is not already in buffer
            # buffer holds msgs that are posted out of order due to latency
            if seq > start and seq not in self.databuffer:
                logger.debug(f'Message newer and not already in buffer.')

                # add seq to data or to self.databuffer
                if self.pseqnum + 1 == seq:
                    self.pseqnum = seq
                    data.append(item.selftext)
                    # remove message
                    if self.delete == True:
                        item.mod.remove()
                    # check if after adding seq to data we can now add from databuffer
                    while True:
                        if self.pseqnum + 1 in self.databuffer:
                            self.pseqnum += 1
                            data.append(self.databuffer[self.pseqnum][0])
                            if self.delete == True:
                                self.userlist[self.curuser].prawR.submission(
                                        id=self.databuffer[self.pseqnum][1]).mod.remove()
                            del self.databuffer[self.pseqnum]
                        else:
                            break
                else:
                    self.databuffer[seq] = (item.selftext,item.id)


                logger.debug(f'Adding data to response')

            
            elif seq in self.databuffer: #already got msg -in databuffer b/c out of order
                assert seq > start
                pass
            else:
                break

        logger.debug(f'Data list returned:\n{data}\n')
        logger.debug(f'Data as string:\n{"".join(data)}\n')

        return data


def main():

    # handle command line arguments 
    parser = argparse.ArgumentParser('soctunnel: A Social Media Tunnel')

    parser.add_argument('-t','--target',action='store', default='0.0.0.0',
            help='local hostname/IP')

    parser.add_argument('-p','--port',type=int, default=random.randint(49152,65535),
            help='local port to listen on/connect to')

    parser.add_argument('-a', '--attach', action='store_const', const='attach',
            default='listen', dest='lmode', 
            help='Attach to local program instead of listening')
    
    parser.add_argument('--site', default='Reddit',
            help='social media site to use')

    parser.add_argument('-l','--listen', action='store_const', const='listen',
            dest='smode', default='client',help='set to listen on social media site')

    parser.add_argument('-v','--verbose', action='count', default = 0, 
            help='Increase verbosity for debugging. Pass vv for more verbosity') 

    parser.add_argument('--no-delete', action='store_false', dest='delete',
            help='Do not delete social media messages for debugging.')

    args = parser.parse_args()

    if args.verbose > 2: 
        args.verbose = 2
    vdict = {0:logging.WARNING, 1:logging.INFO, 2: logging.DEBUG}

    # set up logger

    #stdout
    loghandler = logging.StreamHandler()
    logformatter = logging.Formatter('%(levelname)s:%(message)s')
    loghandler.setFormatter(logformatter)
    logger.addHandler(loghandler)

    logger.setLevel(vdict[args.verbose])

    logger.info('INFO Messages will print')
    logger.debug('DEBUG Messages will print')


    # host,port,site,mode
    tun = Tunnel(host=args.target, port=args.port, site=args.site, smode=args.smode,
            lmode=args.lmode, delete=args.delete)
    signal.signal(signal.SIGINT, tun.close)
    tun.run()


if __name__ == '__main__':
    main()

    
