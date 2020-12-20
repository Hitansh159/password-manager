#! /usr/bin/env python
import numpy as np
import hashlib
import pyperclip 

import psycopg2
from psycopg2 import sql

import tkinter as tk
from tkinter import *
from tkinter import ttk

#############################
# password class 	    #
#############################


class password:
  def __init__(self, id, url, master_pass, gen=False, *args):
    self.ID = id
    self.URL = url
    self.MST = master_pass

    if not gen :
        if args[0] != None:
            self.save_pass(args[0])
        else:
            print("enter password:")
    else:
      self.gen_pass()

  def save_pass(self, key):
    temp0 = 0
    temp1 = 0
    temp2 = 0 

    for i in key:
      temp0 = temp0 * 1000 + ord(i)

    for i in self.MST:
      temp1 = temp1 * 1000 + ord(i)

    for i in self.ID:
      if temp2 >= 2**32-1: break
      temp2 = temp2 * 1000 + ord(i)

    np.random.seed(temp2%2**31)
    salt = np.random.randint(0, temp2%2**31)

    self.passkey = temp0 * temp1 * salt


  def get_pass(self):
    temp1,temp2=0,0

    for i in self.MST:
      temp1 = temp1 * 1000 + ord(i)

    for i in self.ID:
      if temp2 >= 2**32-1: break
      temp2 = temp2 * 1000 + ord(i)

    np.random.seed(temp2%2**31)
    salt = np.random.randint(0, temp2%2**31)

    temp0 =  self.passkey // (temp1* salt)
    key=""

    while(temp0):
      rem = temp0%1000
      key += chr(rem)
      temp0//= 1000

    return key[::-1]

  def gen_pass(self):
    a_array = [chr(i+97) for i in range(23) ]
    A_array = [chr(i+65) for i in range(23) ]
    num_array = [chr(i+49) for i in range(10)]
    sep_char = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
    s=''

    for i in range(11):

      temp0 = np.random.randint(23)
      temp1 = np.random.randint(23)
      temp2 = np.random.randint(10)
      temp3 = np.random.randint(len(sep_char))
      temp = [a_array[temp0], A_array[temp1], num_array[temp2], sep_char[temp3]]

      index = np.random.randint(4)
      s += temp[index]

    self.save_pass(s)


######################################
#  password Database manager	     #
######################################

class password_db:

#	def __init__(self, id, url, master_pass, gen=False, *args):
#		super().__init__(id, url,master_pass, gen, *args)
	def __init__(self, id, master_pass):
		self.ID = id
		self.MST = master_pass

	def db_connect(self):
		self.conn = psycopg2.connect(dbname="password_manager", user="postgres", password="123456")

	def user_outh(self):
		cur = self.conn.cursor()
		cur.execute(
			"SELECT * FROM users WHERE id = %s ;",
			(self.ID,))
		result = cur.fetchone()
		cur.close()
		if result == None:
			self.create_user()
			return self.user_outh()
		elif result[1] == hashlib.sha256(self.MST.encode()).hexdigest() :
			return True
		else:
			return False

	def create_user(self):
		cur = self.conn.cursor()
		cur.execute(
			"INSERT INTO users (id, password) VALUES(%s, %s);",
			(self.ID, hashlib.sha256(self.MST.encode()).hexdigest() ))
		s = "CREATE TABLE %s (url varchar,passkey varchar);" % self.ID
		print(sql.SQL(s))
		cur.execute(sql.SQL(s))
		self.conn.commit()
		cur.execute("SELECT * FROM users")
		print(cur.fetchone())
		cur.close()
	
	def save_password(self, url, passkey):
		cur = self.conn.cursor()
		s = "INSERT INTO {} (url, passkey) VALUES ( %s, %s);".format(self.ID)
		print(sql.SQL(s), (url, passkey))
		cur.execute(sql.SQL(s), (url, passkey))
		self.conn.commit()
		cur.close()

	def get_passwords(self):
		cur = self.conn.cursor()
		cur.execute("SELECT * FROM %s ;" % self.ID)
		result = cur.fetchall()
		print(result)
		return result

"""
def db(url, passkey):
	print("starting")

	conn = psycopg2.connect(dbname="password_manager", user="postgres", password="123456")
	cur = conn.cursor()

	cur.execute(
		"Insert into try (url, passkey) values (%s, %s)", 
		( url, str(passkey)))
	conn.commit()
	cur.execute("SELECT * FROM try;")
	print(cur.fetchone())
	cur.close()
	conn.close()
	print("end")
# $ cd f:/mn/project/'password manager'
"""
######################################
#  APP GUI		 	     #
######################################

LARGEFONT =("Verdana", 35)
NORMALFONT =("Verdana", 25)


class Application(tk.Tk):
	def __init__(self, *args, **kargs):
		tk.Tk.__init__(self, *args, **kargs)
	
		self.container = tk.Frame(self)
		self.container.pack(side = "top", fill = "both", expand = True)

		self.container.grid_rowconfigure(0, weight = 1)
		self.container.grid_columnconfigure(0, weight = 1)
		
		self.db_connection = password_db(None, None)

		self.frames = {}
		self.set_frame()
		self.show_frame(Login)
	
	def set_frame(self):
		for F in (Login, Menu, NewKey, Get):
		
			frame = F(self.container, self)
		
			self.frames[F] = frame
			frame.grid(row=0, column =0 , sticky="nsew")


	def show_frame(self, cont):
		frame = self.frames[cont]
		frame.tkraise()
	

class Login(tk.Frame):
	def __init__(self, parent, controller):
		tk.Frame.__init__(self, parent)
			
		#program title label
		title = ttk.Label(self, text="Password Manager" ,font = LARGEFONT)
		title.grid(row = 0, column = 2, padx = 10, pady = 10)

		label = ttk.Label(self, text="ID: ")
		label.grid(row = 1, column = 1, padx = 10, pady = 10)

		label = ttk.Label(self, text ="Master Password: ")
		label.grid(row = 2, column = 1, padx = 10, pady = 10)

		self.id = StringVar()
		self.password = StringVar()

		id =  ttk.Entry(self, textvariable=self.id)
		id.grid(row = 1, column = 2, padx= 10, pady = 10)
		
		password = ttk.Entry(self, textvariable= self.password, show="*")
		password.grid(row= 2, column = 2, padx = 10, pady = 10)
		
		
		self.sub = ttk.Button(self, text="Login", 
				command = lambda : self.login(controller))
		self.sub.grid(row = 4, column = 2, padx = 10, pady = 10)
	
	def login(self, controller):
		controller.db_connection.ID = self.id.get()
		controller.db_connection.MST = self.password.get()
		self.id.set("")
		self.password.set("")
		controller.db_connection.db_connect()
		if controller.db_connection.user_outh() :
			controller.set_frame()
			controller.show_frame(Menu)
		
		

class Menu(tk.Frame):
	def __init__(self, parent, controller):
		tk.Frame.__init__(self, parent)

		title = ttk.Label(self, text="Password Manager" ,font = LARGEFONT)
		title.grid(row = 0, column = 2, padx = 10, pady = 10)
		
		userid = "ID"
		label = ttk.Label(self, text="Welcome {}".format(userid))
		label.grid(row = 2, column = 2, padx = 10, pady = 10)

		button = ttk.Button(self, text="Add password",
				command = lambda: controller.show_frame(NewKey) )
		button.grid(row = 4, column = 2, padx = 10, pady = 10)

		button = ttk.Button(self, text="Get Password",
				command = lambda: controller.show_frame(Get) )
		button.grid(row = 5, column = 2, padx = 10, pady = 10)

		button = ttk.Button(self, text="LOGOUT",
                                command = lambda: controller.show_frame(Login) )
		button.grid(row = 6, column = 2, padx = 10, pady = 10)

	
class NewKey(tk.Frame):
	def __init__(self, parent, controller):
		tk.Frame.__init__(self, parent)

		title = ttk.Label(self, text="Password Manager" ,font = LARGEFONT)
		title.grid(row = 0, column = 2, padx = 10, pady = 10)
		
		userid = "ID"
		label = ttk.Label(self, text="Welcome {}".format(userid))
		label.grid(row = 2, column = 2, padx = 10, pady = 10)
		
		label = ttk.Label(self, text = "URL: ")
		label.grid(row = 3, column = 2, padx = 10, pady = 10)
	
		label = ttk.Label(self, text = "genrate password: ")
		label.grid(row = 4, column = 2, padx = 10, pady = 10)

		label = ttk.Label(self, text = "Password: ")
		label.grid(row = 5, column = 2, padx = 10, pady = 10)

		v = IntVar()
		url = StringVar()
		password = StringVar()
	
		rb = Radiobutton(self, text='No', variable = v, value = 0)
		rb.grid(row = 4, column = 3, padx = 10, pady = 10)

		rb = Radiobutton(self, text='Yes', variable = v, value = 1)
		rb.grid(row = 4, column = 4, padx = 10, pady = 10)

		textbox =  ttk.Entry(self, textvariable = url)
		textbox.grid(row = 3, column = 3, padx= 10, pady = 10)
		
		textbox = ttk.Entry(self, textvariable = password)
		textbox.grid(row= 5, column = 3, padx = 10, pady = 10)
		
		button = ttk.Button(self, text="Save",
                                command = lambda: self.save_pass(controller, v.get(), url.get(), password.get()) )
		button.grid(row = 6, column = 2, padx = 10, pady = 10)

		button = ttk.Button(self, text="Menu",
                                command = lambda: controller.show_frame(Menu) )
		button.grid(row = 7, column = 2, padx = 10, pady = 10)

	def save_pass(self, controller, gen, url, passkey):
		print(f'gen is {gen}')
		new_pass = password(controller.db_connection.ID, url, controller.db_connection.MST, gen, passkey)
		print(new_pass.get_pass())
		controller.db_connection.save_password(new_pass.URL, new_pass.passkey)
		controller.set_frame()
		controller.show_frame(Menu)

class Get(tk.Frame):
	def __init__(self, parent, controller):
		tk.Frame.__init__(self, parent)

		title = ttk.Label(self, text="Password Manager" ,font = LARGEFONT)
		title.grid(row = 0, column = 2, padx = 10, pady = 10)

		userid = "ID"
		label = ttk.Label(self, text="Welcome {}".format(userid))
		label.grid(row = 2, column = 2, padx = 10, pady = 10)
		
		self.urls = []
		if controller.db_connection.ID != None:
			self.urls = controller.db_connection.get_passwords()
		lb = Listbox(self)

		for i, url in enumerate( self.urls) :
			lb.insert(i, url[0])
		lb.grid(row = 3, column = 2, padx = 10 , pady= 10)
	

		button = ttk.Button(self, text="copy password",
                                command = lambda: self.copy_password(controller, lb.curselection())) 
		button.grid(row = 5, column = 2, padx = 10, pady = 10)
	
		button = ttk.Button(self, text="Menu",
                                command = lambda: controller.show_frame(Menu) )
		button.grid(row = 7, column = 2, padx = 10, pady = 10)
	
	def copy_password(self, controller, url):
		print(self.urls[url[0]])
		passkey = password(controller.db_connection.ID, self.urls[url[0]][0], controller.db_connection.MST, False, "-1")
		passkey.passkey = int(self.urls[url[0]][1])
		pyperclip.copy(passkey.get_pass())

if __name__ == "__main__":
#	user = password_db('hkd159@gmail.com', 'www.gmail.com', 'mass', False, 'pass')
#	user.user_outh()
	app = Application()
	app.mainloop()

## new user entry and authentification on login working as smooth as reqired
## frontend ready and working
# user can enter a url and either genrate or enter password to be stored
# (this is possible with password classed used seprately and object created when required)
# work with fronted and integrate tograteher 
###### (CURRENT ISSUE : all classes work sepratly and don't share recsources)
