# This file will contain any functions needed to add/update/retrieve
# data from the database.
import mysql.connector
import bcrypt

dbuser = 'user'
dbpw = 'changeme'
dbname = 'classchat'
dbhost = 'mysql'

'''
Creating userData table
"CREATE TABLE IF NOT EXISTS userData (id INT AUTO_INCREMENT PRIMARY KEY, username TEXT, password TEXT, FirstName TEXT, LastName TEXT, ProfilePictureUrl TEXT, LoggedIn BOOLEAN)"

Registering a user
INSERT INTO userData (username, password, Firstname, LastName, ProfilePictureUrl, LoggedIn?)
VALUES (JesseIsCool, ScalaIsBestLanguage, Jesse,Hartloff,/images/JesseIsCool.jpg, FALSE)

Creating message table
Channel name goes in alphabetical order of the users Ex: JeffJesse
"CREATE TABLE IF NOT EXISTS messageData (id INT AUTO_INCREMENT PRIMARY KEY, Channel TEXT, Message TEXT, Sender TEXT, Receiver TEXT)"

Inserting into messageData table
"INSERT INTO messageData (Channel, Message, Sender, Receiver) 
VALUES "JeffJesse", "Hey lets give that dead inside group an A", "Jesse", "Jeff"

Creating authentification table
"CREATE TABLE IF NOT EXISTS userTokens (id INT AUTO_INCREMENT PRIMARY KEY, username TEXT, token TEXT)"


Getting the username from an authentification token
SELECT username FROM userTokens
WHERE token= insert hashed token here


Logging in a user
SELECT username, password FROM userData
WHERE username= formData[username] AND password= formData[password]

If a row gets returned then update the table
UPDATE userData
SET LoggedIn = TRUE
WHERE username = formData[username] AND password= formData[password]

Getting all logged in users
SELECT * FROM userData
WHERE LoggedIn = TRUE

""

 '''

def db_init():
    # Initializes server tables if they don't already exist.
    connection = mysql.connector.connect(user=dbuser, password=dbpw, database=dbname, host=dbhost)
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS userData (id INT AUTO_INCREMENT PRIMARY KEY, username TEXT, password BINARY(60), FirstName TEXT, LastName TEXT, ProfilePictureUrl TEXT, LoggedIn BOOLEAN)")
    cursor.execute("CREATE TABLE IF NOT EXISTS messageData (id INT AUTO_INCREMENT PRIMARY KEY, channel TEXT, message TEXT, sender TEXT, recipient TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS userTokens (id INT AUTO_INCREMENT PRIMARY KEY, username TEXT, token BINARY(60))")
    connection.close()

def db_check_user_exists(username: str) -> bool:
    # Checks whether a username is already taken/the user exists.
    connection = mysql.connector.connect(user=dbuser, password=dbpw, database=dbname, host=dbhost)
    cursor = connection.cursor()
    sqlToExecute = "SELECT * FROM userData WHERE username = %s"
    usernameToCheck = (username, )
    cursor.execute(sqlToExecute, usernameToCheck)
    getData = cursor.fetchall()
    # Return True if the user exists
    if len(getData) >= 1:
        connection.close()
        return True
    # Otherwise return False
    connection.close()
    return False

def db_insert_user(username: str, password_hash: bytes, firstName: str, lastName: str, profilePictureUrl: str) -> bool:
    # Inserts a user into userData. Returns True if successful, 
    # False if username is taken/registration failed.
    if not db_check_user_exists(username):
        connection = mysql.connector.connect(user=dbuser, password=dbpw, database=dbname, host=dbhost)
        cursor = connection.cursor()
        sqlInsertion = "INSERT INTO userData (username, password, FirstName, LastName, ProfilePictureUrl, LoggedIn) VALUES (%s, %s, %s, %s, %s, %s)"
        sqlPrepareValues = (username, password_hash, firstName, lastName, profilePictureUrl, False)
        cursor.execute(sqlInsertion, sqlPrepareValues)
        connection.commit()
        connection.close()
        return True
    return False

def db_login_user(username: str, password: str) -> bool:
    # Takes a username and an unhashed password as parameters.
    # If the user exists, gets the hashed password tied to that
    # user from the database. If the hashed password is the same
    # as the input password, returns True. Otherwise, returns False.
    if db_check_user_exists(username): 
        connection = mysql.connector.connect(user=dbuser, password=dbpw, database=dbname, host=dbhost)
        cursor = connection.cursor()
        sqlRetrieval = "SELECT username, password FROM userData WHERE username = %s"
        sqlPrepareUsername = (username, )
        cursor.execute(sqlRetrieval, sqlPrepareUsername)
        retrieved_password = cursor.fetchone()[1]
        if bcrypt.checkpw(password.encode(), bytes(retrieved_password)):
            sqlUpdate = "UPDATE userData SET login = True WHERE username = %s"
            cursor.execute(sqlUpdate, sqlPrepareUsername)
            connection.commit()
            connection.close()
            return True
        connection.close()
    return False

def db_insert_auth_token(username: str, auth_token_hash: bytes):
    # ONLY use this function if the user has been successfully
    # logged in!!!
    #
    # Takes a username and a hashed authentication token as parameters.
    # Does not check whether the username exists (since we assume that
    # the user has already been authenticated), but directly inserts
    # the username and hashed token into userTokens. Does not return
    # any output 
    connection = mysql.connector.connect(user=dbuser, password=dbpw, database=dbname, host=dbhost)
    cursor = connection.cursor()
    sqlInsertion = "INSERT INTO userTokens (username, token) VALUES (%s, %s)"
    sqlPrepareValues = (username, auth_token_hash)
    cursor.execute(sqlInsertion, sqlPrepareValues)
    connection.commit()
    connection.close()

def db_check_auth_token(auth_token: str) -> str:
    # Checks whether the provided (unhashed) authentication token 
    # matches a hashed token in the database. If so, returns
    # the username attached to the token. If not, returns None.
    connection = mysql.connector.connect(user=dbuser, password=dbpw, database=dbname, host=dbhost)
    cursor = connection.cursor()
    sqlRetrieval = "SELECT username, token FROM userTokens"
    cursor.execute(sqlRetrieval)
    retrieved_pairs = cursor.fetchall()
    for pair in retrieved_pairs:
        if bcrypt.checkpw(auth_token.encode(), bytes(pair[1])):
            connection.close()
            return pair[0]
    connection.close()
    return None

def db_retrieve_list_of_users() -> list[tuple[str, str]]:
    # Retrieves a list of tuples, each containing one user
    # and their online status.
    connection = mysql.connector.connect(user=dbuser, password=dbpw, database=dbname, host=dbhost)
    cursor = connection.cursor()
    returnList = []
    sqlRetrieval = "SELECT username, LoggedIn FROM userData"
    cursor.execute(sqlRetrieval)
    retrieved_pairs = cursor.fetchall()
    for pair in retrieved_pairs:
        if pair[1] == True:
            returnList.append((pair[0], "Online"))
        else:
            returnList.append((pair[0], "Offline"))
    connection.close()
    return returnList

def db_logout(username: str):
    # Changes a user's online status to offline.
    connection = mysql.connector.connect(user=dbuser, password=dbpw, database=dbname, host=dbhost)
    cursor = connection.cursor()
    sqlUpdate = "UPDATE userData SET login=False WHERE username=%s"
    sqlPrepareUsername = (username, )
    cursor.execute(sqlUpdate, sqlPrepareUsername)
    connection.commit()
    connection.close()

def db_insert_message(channel: str, sender: str, recipient: str, message: str):
    # Inserts a message into the database.
    connection = mysql.connector.connect(user=dbuser, password=dbpw, database=dbname, host=dbhost)
    cursor = connection.cursor()
    sqlInsertion = "INSERT INTO messageData (channel, message, sender, recipient) VALUES (%s, %s, %s, %s)"
    sqlPrepareValues(channel, message, sender, recipient)
    cursor.execute(sqlInsertion, sqlPrepareValues)
    connection.commit()
    connection.close()

def db_retrieve_channel_messages(channel: str) -> list[tuple[str, str, str]]:
    # Retrieves all messages tied to a specific channel
    # on the site. Returns a list of tuples containing their
    # sender, recipient, and the content of the message itself.
    return None

def db_retrieve_dms(sender: str, recipient: str) -> list[tuple[str, str, str]]:
    # Retrieves a user's DMs with another specific user.
    # Returns a tuple containing each DM's sender, recipient,
    # and the content of each message.
    return None