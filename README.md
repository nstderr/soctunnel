# soctunnel  

This program creates a tunnel through social media. Currently only reddit is supported but more sites to follow. 
Each endpoint of the tunnel connects to a local socket. The endpoint can either listen for local connections or attach
to a program that's already listening. 


<h2>Command line arguments:</h2>  

Flag | Description
----------------------|---------
-v, --verbose |           Verbose. Provides more information about what's going on under the hood. Pass -vv for debugging.
--site |                  Choose site. Currently only Reddit is supported. Reddit is the default if --site is omitted
-a, --attach |            Attach to program listening on local socket. Default is to set tunnel endpoint to listen
-l, --listen |            Set endpoint to listen on site. Default is client mode that initiates site connection. One endpoint must be set to listen and one must be             in client (Default) mode.
-p, --port |              Choose local port to listen on. Default is to pick a random port between 49,152 - 65,535
-t, --target |            Choose local address to listen on. Default is all addresses (0.0.0.0)
-h, --help |              Print help message

<h2>Site Users:</h2>  

Users are taken from environment variables that start with ST_usernameX where
X is an integer starting from 1 and incrementing for each user. Other required environment variables
are described for each site below. Note: some sites only support one user due to spam filters

Example environment file for linux:

    export ST_username1='soctunnel1'  
    export ST_username2='soctunnel2'  
    export ST_username3='soctunnel3'  

The more users, the faster the tunnel will transmit data.

<h2>Supported Sites:</h2>  

<h3>Reddit:</h3>  
  
NOTE: Reddit currently only supports one user. Multiple users will work for a short time but then reddit will
shadow ban the accounts due to automated spam filtering. After being shadow banned, the individual accounts can still see their own messages 
but not each other's. If only one account is used, the shadow ban doesn't affect tunnel functionality. 

TODO: Working on ways to avoid the spam filter. Possible ideas include adding a comment bot to engage with
each message and splitting up the base64 data into "words" so it doesn't appear to be a block of seemingly random characters.

**Api Key Setup:**  
User is set up with "web app" type api key (for future functionality that will include multiple users)  
    
    Step 1: Create reddit account and visit: https://reddit.com/prefs/apps  
    Step 2: Create web app type app. Set the "redirect uri" to: http://127.0.0.1:1  
    Step 3: Set the environment variable ST_clientID to the app's client ID  
    Step 4: Set the environment variable ST_secret to the app's secret  

**Subreddit Setup:**  
A private subreddit needs to be created. This can be created by any account that has enough karma but the user created above under the API Key Setup section
needs to be a moderator. Set the environment variable ST_subreddit to this subreddit's name

**Example environment variables file in linux:**  

    # env.txt
    export ST_subreddit='Subreddit'  
    export ST_secret='User1secret'  
    export ST_clientID='User1clientid'  
    export ST_username1='User1'  
    export ST_password1='User1password'  


<h2>Example usage with Netcat:</h2>  
  
**Step 0:** Load environment variables if they haven't already been loaded. One method is to put them into a file as described above, env.txt and then source the file:    

In linux:  
    
    . ./env.txt  

**Step 1:** Set netcat listener on each computer.  

Computer 1:  
    
    $ nc -nvlp 1111  

Computer 2:  
    
    $ nc -nvlp 2222  

**Step 2:** Set up tunnel and connect to netcat on each computer:  

Computer 1:  

    ./soctunnel.py -a -l -p 1111  

Computer 2:  
    
    ./soctunnel.py -a -p 2222  

Note: -a flag because we already have netcat listening on a local port on each computer. -l flagà because one of the computers needs to pass the -l flag to listen on the social media site. It doesn't matter which one.  

**Closing the connection:**  
At this point the tunnel will be built and the netcat clients will be able to talk to each other. To close the connection, on one endpoint send SIGINT (crtl-c) to the local program (netcat in the above example). This will also close the other side.




