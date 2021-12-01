# This file will contain any functions needed to add/update/retrieve
# data from the database.
import mysql.connector

dbuser = 'root'
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
    cursor.execute("CREATE TABLE IF NOT EXISTS userData (id INT AUTO_INCREMENT PRIMARY KEY, username TEXT, password TEXT, FirstName TEXT, LastName TEXT, ProfilePictureUrl TEXT, LoggedIn BOOLEAN)")
    cursor.execute("CREATE TABLE IF NOT EXISTS messageData (id INT AUTO_INCREMENT PRIMARY KEY, channel TEXT, message TEXT, sender TEXT, recipient TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS userTokens (id INT AUTO_INCREMENT PRIMARY KEY, username TEXT, token TEXT)")
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