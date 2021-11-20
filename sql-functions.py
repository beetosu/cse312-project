# This file will contain any functions needed to add/update/retrieve
# data from the database.

import mysql.connector

connection = mysql.connector.connect(user='root', password='changeme', database='classchat')

connection.close()