from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
from flask.ext.bcrypt import Bcrypt
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "shh"
mysql = MySQLConnector(app, 'TheWall')

@app.route('/')
def index():
	return render_template('main.html')

@app.route('/register', methods = ['POST'])
def register():
	error_count = 0
	if not EMAIL_REGEX.match(request.form['email']):
		flash("Email is not a valid email address")
		error_count += 1
	if len(request.form['first_name']) < 2:
		flash("First name must be longer than 2 characters")
		error_count += 1
	if not request.form['first_name'].isalpha():
		flash('First name must be only alphabetical letters')
		error_count += 1
	if len(request.form['last_name']) < 2:
		flash("Last name must be longer than 2 characters")
		error_count += 1
	if not request.form['last_name'].isalpha():
		flash('Last name must be only alphabetical letters')
		error_count += 1
	if len(request.form['password']) < 8:
		flash('Password must be at least 8 characters long')
	if error_count > 0:
		return redirect('/')
	if error_count == 0:
		query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (:first_name, :last_name, :email, :password, NOW(), NOW())"
		data = {
			'first_name':request.form['first_name'],
			'last_name':request.form['last_name'],
			'email':request.form['email'],
			'password': bcrypt.generate_password_hash(request.form['password'])
		}
		mysql.query_db(query, data)
		return redirect('/')
	else:
		flash('Confirm Password must match password')
		return redirect('/')

@app.route('/login', methods = ['POST'])
def login_form():
	error_count = 0
	if not EMAIL_REGEX.match(request.form['loginemail']):
		flash("Email is not a valid email address")
		error_count += 1
	if len(request.form['loginemail']) < 1:
		flash('Login email cannot be empty!')
		error_count += 1
	if len(request.form['loginpassword']) < 1:
		flash ('Password cannot be empty!')
		error_count += 1
	if error_count > 0:
		return redirect('/')
	else:
		db = login()
		if(db):
			match = bcrypt.check_password_hash(db[0]['password'], request.form['loginpassword'])
			if(match):
				session['active_id'] = db[0]['id']
				session['active_name'] = db[0]['first_name']
				return redirect('/wall')
		else:
			flash('Email/Password is incorrect')
			return redirect('/wall')
def login():
	query = "SELECT id, password, first_name FROM users WHERE email = :email"
	data = { 'email': request.form['loginemail']}
	return mysql.query_db(query, data)

@app.route('/logout')
def logout():
	session.clear()
	return redirect('/')

@app.route('/wall')
def wallpage():
	
	messages = get_messages()
	comments = get_comments()
	return render_template('wall.html', messages = messages, comments = comments)

def get_messages():
	query = "SELECT messages.id, first_name, last_name, messages.message, messages.user_id, messages.created_at FROM users LEFT JOIN messages ON users.id = messages.user_id ORDER BY created_at desc"
	return mysql.query_db(query)

def get_comments():
	query = "SELECT first_name, last_name, comments.id, comments.user_id, comment, comments.created_at, comments.message_id FROM comments LEFT JOIN users ON users.id = comments.user_id ORDER BY created_at desc"
	return mysql.query_db(query)

@app.route('/usermessage/<id>', methods = ['POST'])
def postmessage(id):
	query = "INSERT INTO messages (message, created_at, updated_at, user_id) VALUES (:message, NOW(), NOW(), :active_id)"
	data = {
		'message': request.form['messagebox'],
		'active_id': session['active_id']
	}
	mysql.query_db(query, data)
	return redirect('/wall')


@app.route('/usercomment', methods = ['POST'])
def postcomment():
	query = "INSERT INTO comments (comment, created_at, updated_at, user_id, message_id) VALUES (:comment, NOW(), NOW(), :active_id, :message_id)"
	data = {
		'comment': request.form['commentbox'],
		'active_id': session['active_id'],
		'message_id': request.form['message_id']
	}
	mysql.query_db(query, data)
	return redirect('/wall')

@app.route('/deletemessage/<message_id>/<message_user_id>')
def delete_message(message_id, message_user_id):
	query = "DELETE FROM messages WHERE messages.id = :message_id"
	data = {
		'message_id': message_id
	}
	mysql.query_db(query,data)
	return redirect('/wall')

@app.route('/deletecomment/<comment_id>/<comment_user_id>')
def delete_comment(comment_id, comment_user_id):
	query = "DELETE FROM comments WHERE comments.id = :comment_id"
	data = {
		'comment_id': comment_id
	}
	mysql.query_db(query, data)
	return redirect('/wall')

















app.run(debug=True)