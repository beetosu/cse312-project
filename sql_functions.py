# This file will contain any functions needed to add/update/retrieve
# data from the database.

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
import mysql.connector

connection = mysql.connector.connect(user='root', password='changeme', database='classchat')

connection.close()