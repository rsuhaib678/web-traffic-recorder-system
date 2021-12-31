#!/usr/bin/env python

# This is a simple web server for a traffic counting application.
# It's your job to extend it by adding the backend functionality to support
# recording the traffic in a SQL database. You will also need to support
# some predefined users and access/session control. You should only
# need to extend this file. The client side code (html, javascript and css)
# is complete and does not require editing or detailed understanding.

# import the various libraries needed
import http.cookies as Cookie # some cookie handling support
from http.server import BaseHTTPRequestHandler, HTTPServer # the heavy lifting of the web server
import urllib # some url parsing support
import hashlib
from datetime import datetime
import json # support for json encoding
import sys # needed for agument handling
import sqlite3
import time
import random
from datetime import datetime, timedelta

def access_database(dbfile, query):
    connect = sqlite3.connect(dbfile)
    cursor = connect.cursor()
    cursor.execute(query)
    connect.commit()
    connect.close()


# access_database requires the name of an sqlite3 database file and the query.
# It returns the result of the query
def access_database_with_result(dbfile, query):
    connect = sqlite3.connect(dbfile)
    cursor = connect.cursor()
    rows = cursor.execute(query).fetchall()
    connect.commit()
    connect.close()
    return rows


def setup_assessment_tables(dbfile):
    
    access_database(dbfile, "DROP TABLE IF EXISTS users")
    access_database(dbfile, "DROP TABLE IF EXISTS session")
    access_database(dbfile, "DROP TABLE IF EXISTS traffic")

    # Freshly setup tables
    access_database(dbfile, "CREATE TABLE  users (userid INTEGER PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL)")
    access_database(dbfile, "CREATE TABLE  session (sessionid INTEGER PRIMARY KEY, userid INTEGER, magic TEXT NOT NULL, start INTEGER, end INTEGER)")
    access_database(dbfile, "CREATE TABLE  traffic (recordid INTEGER PRIMARY KEY, sessionid INTEGER, time INTEGER, type INTEGER, occupancy INTEGER, location TEXT NOT NULL, mode INTEGER)")
    access_database(dbfile, "INSERT INTO users VALUES(1,'test1','password1')")
    access_database(dbfile, "INSERT INTO users VALUES(2,'test2','password2')")
    access_database(dbfile, "INSERT INTO users VALUES(3,'test3','password3')")
    access_database(dbfile, "INSERT INTO users VALUES(4,'test4','password4')")
    access_database(dbfile, "INSERT INTO users VALUES(5,'test5','password5')")
    access_database(dbfile, "INSERT INTO users VALUES(6,'test6','password6')")
    access_database(dbfile, "INSERT INTO users VALUES(7,'test7','password7')")
    access_database(dbfile, "INSERT INTO users VALUES(8,'test8','password8')")
    access_database(dbfile, "INSERT INTO users VALUES(9,'test9','password9')")
    access_database(dbfile, "INSERT INTO users VALUES(10,'test10','password10')")


setup_assessment_tables("traffic.db")

now_time = int(time.time())
# user_name1 = access_database_with_result("traffic.db","SELECT COUNT (*) FROM (SELECT * FROM session LEFT JOIN users ON session.userid=users.userid)")
# access_database_with_result("traffic.db","UPDATE session SET end = {} ".format(now_time))
# get_sessionid2 = access_database_with_result("traffic.db","SELECT * FROM session ")

def build_response_refill(where, what):
    """This function builds a refill action that allows part of the
       currently loaded page to be replaced."""
    return {"type":"refill","where":where,"what":what}

def build_response_redirect(where):
    """This function builds the page redirection action
       It indicates which page the client should fetch.
       If this action is used, only one instance of it should
       contained in the response and there should be no refill action."""
    return {"type":"redirect", "where":where}

def handle_validate(iuser, imagic):
    """Decide if the combination of user and magic is valid"""

    ## alter as required
    credential = access_database_with_result("traffic.db",f"SELECT username, magic FROM (SELECT * FROM users LEFT JOIN session ON users.userid=session.userid)where end = 0 AND username = '{iuser}' AND magic = '{imagic}'")
     
     
    if (credential != None):
        return True
    else:
        return False

def handle_delete_session(iuser, imagic):
    """Remove the combination of user and magic from the data base, ending the login"""
    if(imagic != ''):
        now=datetime.now()
        access_database("traffic.db",f"update session SET end='{now}' WHERE magic='{imagic}' ")
    return

def handle_login_request(iuser, imagic, parameters):
    """A user has supplied a username (parameters['usernameinput'][0])
       and password (parameters['passwordinput'][0]) check if these are
       valid and if so, create a suitable session record in the database
       with a random magic identifier that is returned.
       Return the username, magic identifier and the response action set."""
    
    if handle_validate(iuser, imagic) == True:
        # the user is already logged in, so end the existing session.
        handle_delete_session(iuser, imagic)

    response = []
    ## alter as required

    
    user_name = access_database_with_result("traffic.db","SELECT username FROM users")
    pass_word = access_database_with_result("traffic.db","SELECT password FROM users")
    user_list = []
    pass_list = []

    for i in range(0, len(user_name)):
        user_list.append(user_name[i][0])
        pass_list.append(pass_word[i][0])

    if 'passwordinput' not in parameters or 'usernameinput' not in parameters:
        response.append(build_response_refill('message', 'Invalid username/password'))
        user = ''
        magic = ''
        return [user, magic, response]
    else:
        if parameters['usernameinput'][0] in user_list and parameters['passwordinput'][0] in pass_list: ## The user is valid
        
            user1=access_database_with_result("traffic.db",f"SELECT userid FROM users WHERE  username = '{parameters['usernameinput'][0]}' ")
            session1=access_database_with_result("traffic.db",f"SELECT COUNT(*) FROM session WHERE  userid = {user1[0][0]} AND end IS NULL")
            records = session1
            if (records[0][0]) >= 1:
                response.append(build_response_refill('message', 'User has already logged in'))
                user = ''
                magic = ''
                return [user, magic, response]  
            
            else:      
                response.append(build_response_redirect('/page.html'))
                user = parameters['usernameinput'][0]
                magic = "%0.12d" % random.randint(1000000000000,9999999999999)

                now_exact_time = datetime.now()
                user2 = access_database_with_result("traffic.db",f"SELECT userid FROM users WHERE  username = '{user}' ")
                access_database("traffic.db",f"INSERT INTO session (userid, start, magic) VALUES  ('{user2[0][0]}','{now_exact_time}',{magic}) ")             

                return [user, magic, response]   
 
        else:
            response.append(build_response_refill('message', 'Invalid password'))
            # response.append(build_response_redirect('/index.html'))
            user = '!'
            magic = ''    
            return [user, magic, response]

def handle_add_request(iuser, imagic, parameters):
    """The user has requested a vehicle be added to the count
       parameters['locationinput'][0] the location to be recorded
       parameters['occupancyinput'][0] the occupant count to be recorded
       parameters['typeinput'][0] the type to be recorded
       Return the username, magic identifier (these can be empty  strings) and the response action set."""
    response = []
    
    # alter as required

    if handle_validate(iuser, imagic) != True:
        #Invalid sessions redirect to login
        response.append(build_response_redirect('/index.html'))
        user = '!'
        magic = ''
        return [user, magic, response]
    
    else:

        if 'locationinput' not in parameters:

            response.append(build_response_refill('message', 'Please enter location'))
            
            get_sessionid1= access_database_with_result("traffic.db",f"SELECT sessionid FROM session WHERE  magic='{imagic}' ")
             
            count_traffic= access_database_with_result("traffic.db",f"SELECT COUNT (*) FROM traffic WHERE sessionid ={get_sessionid1[0][0]} AND mode = 1 ")
             
            response.append(build_response_refill('total', str(count_traffic[0][0])))
            user = ''
            magic = ''
            return [user, magic, response]
            
        else: ## a valid session so process the addition of the entry.
            location = parameters['locationinput'][0]
            types = parameters['typeinput'][0]  
            occupancy = parameters['occupancyinput'][0]
            now = datetime.now()
            vehicles = {}
            vehicles["vehicle"] = ['car','taxi','bus','bicycle','motorbike','van','truck','other']
              
            if types not in vehicles["vehicle"]:
                               
                response.append(build_response_refill('message', 'Unknown vehicle'))
                response.append(build_response_refill('total', '0'))
                user = ''
                magic = ''
                return [user, magic, response]

            else:
                get_userid1= access_database_with_result("traffic.db",f"select userid from users where username='{iuser}' ")
                get_sessionid2= access_database_with_result("traffic.db",f"select sessionid from session where userid={get_userid1[0][0]} AND magic='{imagic}'")   
                access_database("traffic.db",f"INSERT INTO traffic (sessionid, time, type, occupancy, location, mode) VALUES  ({get_sessionid2[0][0]},'{now}','{types}',{occupancy},'{location}',1) ")
                tr1 = access_database_with_result("traffic.db",f"select COUNT(mode) from traffic where mode = 1 AND sessionid={get_sessionid2[0][0]} ")
                response.append(build_response_refill('message', 'Entry added.'))
                response.append(build_response_refill('total', str(tr1[0][0])))
                user = ''
                magic = ''
                return [user, magic, response]

def handle_undo_request(iuser, imagic, parameters):
    """The user has requested a vehicle be removed from the count
       This is intended to allow counters to correct errors.
       parameters['locationinput'][0] the location to be recorded
       parameters['occupancyinput'][0] the occupant count to be recorded
       parameters['typeinput'][0] the type to be recorded
       Return the username, magic identifier (these can be empty  strings) and the response action set."""
    response = []
    
    ## alter as required
    if handle_validate(iuser, imagic) != True:
        #Invalid sessions redirect to login
        response.append(build_response_redirect('/index.html'))
        user = '!'
        magic = ''
        return [user, magic, response]
        
    else: ## a valid session so process the recording of the entry.

        if 'locationinput' not in parameters:
            
            response.append(build_response_refill('message', 'Please enter location'))  #(*needs to be discussed)
            session_id = access_database_with_result("traffic.db",f"SELECT sessionid FROM session WHERE  magic='{imagic}' ")
            cnt_tr = access_database_with_result("traffic.db",f"SELECT COUNT(*) FROM traffic WHERE mode=1 AND sessionid={session_id[0][0]} ")
            total = cnt_tr
            response.append(build_response_refill('total', str(total[0][0])))
            user = ''
            magic = ''
            return [user, magic, response]

        else:
            location = parameters['locationinput'][0]
            types = parameters['typeinput'][0]
            occupancy = parameters['occupancyinput'][0]

            vehicles = {}
            vehicles["vehicle"] = ['car','taxi','bus','bicycle','motorbike','van','truck','other']
            
            if parameters['typeinput'][0] not in vehicles["vehicle"]:
                response.append(build_response_refill('message', 'Unknown vehicle'))
                response.append(build_response_refill('total', '0'))
                user = ''
                magic = ''
                return [user, magic, response]

            else:
                session_id0 = access_database_with_result("traffic.db",f"SELECT sessionid FROM session WHERE  magic='{imagic}' ")
                max_rcd = access_database_with_result("traffic.db",f"SELECT MAX(recordid) FROM traffic WHERE mode = 1 AND\
                    sessionid={session_id0[0][0]} AND location = '{location}' AND type = '{types}' AND occupancy = {occupancy} ")
                record_count = max_rcd
                if record_count[0][0] == None:
                    response.append(build_response_refill('message', 'Record does not exist.'))
                else:
                    session_id1 = access_database_with_result("traffic.db",f"SELECT sessionid FROM session WHERE  magic='{imagic}' ")
                    access_database("traffic.db",f"UPDATE traffic SET mode = 0 WHERE recordid = (SELECT MAX(recordid) FROM traffic WHERE mode = 1\
                            AND sessionid={session_id1[0][0]} AND location = '{location}' AND type = '{types}' AND occupancy = {occupancy}) ")
                    
                    response.append(build_response_refill('message', 'Entry Un-done.'))         
                    session_id2 = access_database_with_result("traffic.db",f"SELECT sessionid FROM session WHERE  magic='{imagic}' ")
                    cnt_tr = access_database_with_result("traffic.db",f"SELECT COUNT(*) FROM traffic WHERE mode = 1 AND sessionid = {session_id2[0][0]} ")
                    record_count = cnt_tr
                    response.append(build_response_refill('total', str(record_count[0][0])))
                user = ''
                magic = ''
                return [user, magic, response]




def handle_back_request(iuser, imagic, parameters):
    """This code handles the selection of the back button on the record form (page.html)
       You will only need to modify this code if you make changes elsewhere that break its behaviour"""
    response = []
    ## alter as required
    if handle_validate(iuser, imagic) != True:
        response.append(build_response_redirect('/index.html'))
    else:
        response.append(build_response_redirect('/summary.html'))
    user = ''
    magic = ''
    return [user, magic, response]


def handle_logout_request(iuser, imagic, parameters):
    """This code handles the selection of the logout button on the summary page (summary.html)
       You will need to ensure the end of the session is recorded in the database
       And that the session magic is revoked."""
    response = []
    ## alter as required

    if imagic != '':
        now_time = datetime.now()
        access_database("traffic.db",f"UPDATE session SET end = '{now_time}' WHERE  magic='{imagic}'")

    response.append(build_response_redirect('/index.html'))
    user = '!'
    magic = ''
    return [user, magic, response]


def handle_summary_request(iuser, imagic, parameters):
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    ## alter as required
    if handle_validate(iuser, imagic) != True:
        response.append(build_response_redirect('/index.html'))
        user = '!'
        magic = ''
        return [user, magic, response]
    else:
        
        sessions = access_database_with_result("traffic.db",f"SELECT sessionid FROM session WHERE  magic='{imagic}' ")
        car_query = access_database_with_result("traffic.db",f"SELECT COUNT(*) FROM traffic WHERE mode = 1 AND sessionid = {sessions[0][0]} AND type = 'car'")

        # session_taxi = access_database_with_result("traffic.db","SELECT sessionid FROM session WHERE  magic={} ".format(imagic))
        taxi_query = access_database_with_result("traffic.db",f"SELECT COUNT(*) FROM traffic WHERE mode = 1 AND sessionid = {sessions[0][0]} AND type = 'taxi'")

        # session_bus = access_database_with_result("traffic.db","SELECT sessionid FROM session WHERE  magic={} ".format(imagic))
        bus_query = access_database_with_result("traffic.db",f"SELECT COUNT(*) FROM traffic WHERE mode = 1 AND sessionid = {sessions[0][0]} AND type = 'bus'")

        # session_motorbike = access_database_with_result("traffic.db","SELECT sessionid FROM session WHERE  magic={} ".format(imagic))
        motorbike_query = access_database_with_result("traffic.db",f"SELECT COUNT(*) FROM traffic WHERE mode = 1 AND sessionid = {sessions[0][0]} AND type = 'motorbike'")

        # session_bicycle = access_database_with_result("traffic.db","SELECT sessionid FROM session WHERE  magic={} ".format(imagic))
        bicycle_query = access_database_with_result("traffic.db",f"SELECT COUNT(*) FROM traffic WHERE mode = 1 AND sessionid = {sessions[0][0]} AND type = 'bicycle'")

        # session_van = access_database_with_result("traffic.db","SELECT sessionid FROM session WHERE  magic={} ".format(imagic))
        van_query = access_database_with_result("traffic.db",f"SELECT COUNT(*) FROM traffic WHERE mode = 1 AND sessionid = {sessions[0][0]} AND type = 'van'")

        # session_truck = access_database_with_result("traffic.db","SELECT sessionid FROM session WHERE  magic={} ".format(imagic))
        truck_query = access_database_with_result("traffic.db",f"SELECT COUNT(*) FROM traffic WHERE mode = 1 AND sessionid = {sessions[0][0]} AND type = 'truck'")

        # session_other = access_database_with_result("traffic.db","SELECT sessionid FROM session WHERE  magic={} ".format(imagic))
        other_query = access_database_with_result("traffic.db",f"SELECT COUNT(*) FROM traffic WHERE mode = 1 AND sessionid = {sessions[0][0]} AND type = 'other'")

        # session_tot = access_database_with_result("traffic.db","SELECT sessionid FROM session WHERE  magic={} ".format(imagic))
        tot_query = access_database_with_result("traffic.db",f"SELECT COUNT(*) FROM traffic WHERE mode = 1 AND sessionid = {sessions[0][0]} ")
        
        response.append(build_response_refill('sum_car', str(car_query[0][0])))
        response.append(build_response_refill('sum_taxi', str(taxi_query[0][0])))
        response.append(build_response_refill('sum_bus', str(bus_query[0][0])))
        response.append(build_response_refill('sum_motorbike', str(motorbike_query[0][0])))
        response.append(build_response_refill('sum_bicycle', str(bicycle_query[0][0])))
        response.append(build_response_refill('sum_van', str(van_query[0][0])))
        response.append(build_response_refill('sum_truck', str(truck_query[0][0])))
        response.append(build_response_refill('sum_other', str(other_query[0][0])))
        response.append(build_response_refill('total', str(tot_query[0][0])))
        user = ''
        magic = ''
    return [user, magic, response]


# HTTPRequestHandler class
class myHTTPServer_RequestHandler(BaseHTTPRequestHandler):

    # GET This function responds to GET requests to the web server.
    def do_GET(self):

        # The set_cookies function adds/updates two cookies returned with a webpage.
        # These identify the user who is logged in. The first parameter identifies the user
        # and the second should be used to verify the login session.
        def set_cookies(x, user, magic):
            ucookie = Cookie.SimpleCookie()
            ucookie['u_cookie'] = user
            x.send_header("Set-Cookie", ucookie.output(header='', sep=''))
            mcookie = Cookie.SimpleCookie()
            mcookie['m_cookie'] = magic
            x.send_header("Set-Cookie", mcookie.output(header='', sep=''))

        # The get_cookies function returns the values of the user and magic cookies if they exist
        # it returns empty strings if they do not.
        def get_cookies(source):
            rcookies = Cookie.SimpleCookie(source.headers.get('Cookie'))
            user = ''
            magic = ''
            for keyc, valuec in rcookies.items():
                if keyc == 'u_cookie':
                    user = valuec.value
                if keyc == 'm_cookie':
                    magic = valuec.value
            return [user, magic]

        # Fetch the cookies that arrived with the GET request
        # The identify the user session.
        user_magic = get_cookies(self)

        print(user_magic)

        # Parse the GET request to identify the file requested and the parameters
        parsed_path = urllib.parse.urlparse(self.path)

        # Decided what to do based on the file requested.

        # Return a CSS (Cascading Style Sheet) file.
        # These tell the web client how the page should appear.
        if self.path.startswith('/css'):
            self.send_response(200)
            self.send_header('Content-type', 'text/css')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return a Javascript file.
        # These tell contain code that the web client can execute.
        elif self.path.startswith('/js'):
            self.send_response(200)
            self.send_header('Content-type', 'text/js')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # A special case of '/' means return the index.html (homepage)
        # of a website
        elif parsed_path.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('./index.html', 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return html pages.
        elif parsed_path.path.endswith('.html'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('.'+parsed_path.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # The special file 'action' is not a real file, it indicates an action
        # we wish the server to execute.
        elif parsed_path.path == '/action':
            self.send_response(200) #respond that this is a valid page request
            # extract the parameters from the GET request.
            # These are passed to the handlers.
            parameters = urllib.parse.parse_qs(parsed_path.query)

            if 'command' in parameters:
                # check if one of the parameters was 'command'
                # If it is, identify which command and call the appropriate handler function.
                if parameters['command'][0] == 'login':
                    [user, magic, response] = handle_login_request(user_magic[0], user_magic[1], parameters)
                    #The result of a login attempt will be to set the cookies to identify the session.
                    set_cookies(self, user, magic)
                elif parameters['command'][0] == 'add':
                    [user, magic, response] = handle_add_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'undo':
                    [user, magic, response] = handle_undo_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'back':
                    [user, magic, response] = handle_back_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'summary':
                    [user, magic, response] = handle_summary_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'logout':
                    [user, magic, response] = handle_logout_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                else:
                    # The command was not recognised, report that to the user.
                    response = []
                    response.append(build_response_refill('message', 'Internal Error: Command not recognised.'))

            else:
                # There was no command present, report that to the user.
                response = []
                response.append(build_response_refill('message', 'Internal Error: Command not found.'))

            text = json.dumps(response)
            print(text)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(text, 'utf-8'))

        elif self.path.endswith('/statistics/hours.csv'):
            ## if we get here, the user is looking for a statistics file
            ## this is where requests for /statistics/hours.csv should be handled.
            ## you should check a valid user is logged in. You are encouraged to wrap this behavour in a function.
            response=[]

            text = "Username,Day,Week,Month\n"
            text += "test1,0.0,0.0,0.0\n" # not real data
            text += "test2,0.0,0.0,0.0\n"
            text += "test3,0.0,0.0,0.0\n"
            text += "test4,0.0,0.0,0.0\n"
            text += "test5,0.0,0.0,0.0\n"
            text += "test6,0.0,0.0,0.0\n"
            text += "test7,0.0,0.0,0.0\n"
            text += "test8,0.0,0.0,0.0\n"
            text += "test9,0.0,0.0,0.0\n"
            text += "test10,0.0,0.0,0.0\n"

            

            encoded = bytes(text, 'utf-8')
            self.send_response(200)
            self.send_header('Content-type', 'text/csv')
            self.send_header("Content-Disposition", 'attachment; filename="{}"'.format('hours.csv'))
            self.send_header("Content-Length", len(encoded))
            self.end_headers()
            self.wfile.write(encoded)

        elif self.path.endswith('/statistics/traffic.csv'):
            ## if we get here, the user is looking for a statistics file
            ## this is where requests for  /statistics/traffic.csv should be handled.
            ## you should check a valid user is checked in. You are encouraged to wrap this behavour in a function.
            text = "This should be the content of the csv file."
            text = "Location,Type,Occupancy1,Occupancy2,Occupancy3,Occupancy4\n"
            # text += '"Main Road",car,0,0,0,0\n' # not real data             

            # end of code
            curr_date=datetime.now().date()
            # hsh=access_database_with_result("traffic.db",f"select location from (select * from(select location,type,occupancy,mode,(DATE(time)) as date from traffic) where date='{curr_date}' AND mode=1) ")
            # occ=access_database_with_result("traffic.db",f"select location, type,SUM(occupancy = 1) as Occupancy1 ,\
            #     SUM(occupancy = 2) as Occupancy2, SUM(occupancy = 3) as Occupancy3, SUM(occupancy = 4) as Occupancy4\
            #          FROM traffic WHERE mode = 1 AND (date(time))[0][0] = {curr_date} GROUP BY location, type  ")
            
            traff_csv=access_database_with_result("traffic.db",f"select location, type,SUM(occupancy = 1) as Occupancy1,SUM(occupancy = 2) as Occupancy2, SUM(occupancy = 3) as Occupancy3, SUM(occupancy = 4) as Occupancy4 FROM  (select * from (select location,type,occupancy,mode, (DATE(time)) as Date from traffic ) where Date='{curr_date}' )GROUP BY location, type")
            
            for i in range(len(traff_csv)):
                text += str(traff_csv[i][0]) + "," + str(traff_csv[i][1]) + "," + str(traff_csv[i][2]) + "," + str(traff_csv[i][3]) + "," + str(traff_csv[i][4]) + "," + str(traff_csv[i][5]) + '\n'

            encoded = bytes(text, 'utf-8')
            self.send_response(200)
            self.send_header('Content-type', 'text/csv')
            self.send_header("Content-Disposition", 'attachment; filename="{}"'.format('traffic.csv'))
            self.send_header("Content-Length", len(encoded))
            self.end_headers()
            self.wfile.write(encoded)

        else:
            # A file that does n't fit one of the patterns above was requested.
            self.send_response(404)
            self.end_headers()
        return

def run():
    """This is the entry point function to this code."""
    print('starting server...')
    ## You can add any extra start up code here
    # Server settings
    # Choose port 8081 over port 80, which is normally used for a http server
    if(len(sys.argv)<2): # Check we were given both the script name and a port number
        print("Port argument not provided.")
        return
    server_address = ('127.0.0.1', int(sys.argv[1]))
    httpd = HTTPServer(server_address, myHTTPServer_RequestHandler)
    print('running server on port =',sys.argv[1],'...')
    httpd.serve_forever() # This function will not return till the server is aborted.

run()
