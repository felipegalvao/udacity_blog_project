import os
import re
import hmac
import random
import string
import hashlib
import time

import jinja2
import webapp2

from google.appengine.ext import db

SECRET = "sdac.rtyeysgfd8123ads.rqwefsfd*I&gfh%&!!"

# Functions for hashing and salting
def make_secure_val(val):
	return("%s|%s" % (val,hmac.new(SECRET, val).hexdigest()))

def check_secure_val(secure_val):
	val = secure_val.split("|")[0]
	if secure_val == make_secure_val(val):
		return(val)

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=""):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, pw, h):
    salt = h.split(",")[0]
    if h == make_pw_hash(name, pw, salt):
        return(True)

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							   autoescape=True)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

# Definitions for Post class
class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created_at = db.DateTimeProperty(auto_now_add = True)
	posted_by_id = db.IntegerProperty(required = True)
	likes = db.ListProperty(item_type=int)

# Definitions for User class
class User(db.Model):
	username = db.StringProperty(required = True)
	password_hash = db.StringProperty(required = True)
	email = db.StringProperty

# Definitions for Comment class
class Comment(db.Model):
	associated_post_id = db.IntegerProperty(required = True)
	commenter = db.ReferenceProperty(User)
	content = db.TextProperty(required = True)

# Functions for validation of User information submitted on a form
def username_is_valid(username):
	USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
	return USER_RE.match(username)

def password_is_valid(password):
	PASSWORD_RE = re.compile(r"^.{3,20}$")
	return PASSWORD_RE.match(password)

def email_is_valid(email):
	EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
	return EMAIL_RE.match(email)

# Handler for User Signup
class UserSignupHandler(Handler):
	def get(self):
		# Retrieve the user_id cookie and check if the user is logged in
		user_id_cookie = self.request.cookies.get("user_id")
		if user_id_cookie:
			logged_user_id = int(user_id_cookie.split("|")[0])
			logged_user = User.get_by_id(logged_user_id)
		else:
			logged_user_id = None
			logged_user = None

		# If user is logged in, redirect to main page with warning message
		if logged_user_id:
			self.redirect("/?signup_already_logged_in=true")
		# If not, render the signup form
		else:
			self.render("user_signup.html", logged_user_id=logged_user_id)

	def post(self):
		# Get information from the submitted form
		username = self.request.get("username")
		password = self.request.get("username")
		verify = self.request.get("verify")
		email = self.request.get("email")

		# Create the password_hash with the predefined function
		password_hash = make_pw_hash(username, password)

		# Verification for form fields
		username_message = ""
		password_message = ""
		match_message = ""
		email_message = ""
		user_exists_message = ""
		valid_username = username_is_valid(username)
		if not valid_username:
			username_message = "That's not a valid username."
		valid_password = password_is_valid(password)
		if not valid_password:
			password_message = "That wasn't a valid password."
		if password != verify:
			match_message = "Your passwords didn't match."
		valid_email = email_is_valid(email)
		if email != "" and (not valid_email):
			email_message = "That's not a valid email."

		# Retrieve the user and check if it already exists
		user = User.all().filter('username =', username).get()
		if user:
			user_exists_message = "This username already exists"

		# If any of the error messages is not empty, render the form again. Keep
		# the username and email if provided
		if username_message or password_message or match_message or \
			email_message or user_exists_message:
			self.render("user_signup.html", username_message=username_message,
						password_message=password_message,
						match_message=match_message,
						email_message=email_message,
						user_exists_message=user_exists_message,
						username=username,
						email=email)
		# If the information provided is complete and valid, create the user,
		# set the cookie with user_id and a hash and redirect the user to the
		# Welcome page
		else:
			user = User(username = username, password_hash = password_hash,
						email=email)
			user.put()
			time.sleep(1)
			self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/'
											 % make_secure_val(
											 str(user.key().id())))
			self.redirect("/welcome")

# Handler for loggin users
class LoginHandler(Handler):
	def get(self):
		# Retrieve the user_id cookie and check if the user is logged in
		user_id_cookie = self.request.cookies.get("user_id")
		if user_id_cookie:
			logged_user_id = int(user_id_cookie.split("|")[0])
			logged_user = User.get_by_id(logged_user_id)
		else:
			logged_user_id = None
			logged_user = None

		# If the user is logged in, redirect to main page with error message
		if logged_user_id:
			self.redirect("/?login_already_logged_in=true")
		# If not, render the login form
		else:
			self.render("login.html", logged_user_id=logged_user_id)

	def post(self):
		# Retrieve the information submitted with the login form
		username = self.request.get("username")
		password = self.request.get("password")
		login_message = ""
		# Try to retrieve user with the provided username
		user = User.all().filter('username =', username).get()
		# If the user exists, check if the password is valid
		if user:
			if (user.username == username and
				valid_pw(username, password, user.password_hash)):
				# If password is valid, set cookie for the logged user and
				# redirect to the Welcome page
				self.response.headers.add_header('Set-Cookie',
												 'user_id=%s' % make_secure_val(
												 str(user.key().id())))
				self.redirect("/welcome")
		# If user does not exist or password is invalid, define error message
		# and render login form with it
		login_message = "Invalid login"
		self.render("login.html", login_message=login_message,
					username=username)

# Handler for user logout
class LogoutHandler(Handler):
	def get(self):
		# Set an empty value for the user_id cookie and redirect the user to
		# the signup page
		self.response.headers.add_header('Set-Cookie', 'user_id=;Path=/')
		self.redirect("/user_signup")

class WelcomeHandler(Handler):
	def get(self):
		# Retrieve the user_id cookie and check if the user is logged in
		user_id_cookie = self.request.cookies.get("user_id")
		if user_id_cookie:
			logged_user_id = int(user_id_cookie.split("|")[0])
			logged_user = User.get_by_id(logged_user_id)
		else:
			logged_user_id = None
			logged_user = None

		# If user is logged in and the cookie is valid, render the Welcome page
		# with the username
		if user_id_cookie and check_secure_val(user_id_cookie):
			user_id = int(user_id_cookie.split("|")[0])
			user = User.get_by_id(int(user_id))
			username = user.username
			self.render("welcome.html", username=username,
						logged_user_id=logged_user_id)
		# If not, redirect to signup page
		else:
			self.redirect("/user_signup")

# Handler for the Blog's main page
class MainPageHandler(Handler):
	def get(self):
		# Retrieve all posts, ordered by creation date
		posts = Post.all().order('-created_at')

		# Retrieve the user_id cookie and check if the user is logged in
		user_id_cookie = self.request.cookies.get("user_id")
		if user_id_cookie:
			logged_user_id = int(user_id_cookie.split("|")[0])
			logged_user = User.get_by_id(logged_user_id)
		else:
			logged_user_id = None
			logged_user = None

		# If there is any error message variable defined in the get request
		# define the error messages and render the main page with it
		error_message = ""
		if self.request.get("signup_already_logged_in") == "true":
			error_message = "You must be logged out to sign up."
		elif self.request.get("login_already_logged_in") == "true":
			error_message = "You are already logged in."
		self.render("front.html", posts=posts, logged_user_id=logged_user_id,
					logged_user=logged_user, error_message=error_message)

# Handler for the creation of posts in the blog
class NewPostHandler(Handler):
	def get(self):
		# Retrieve the user_id cookie and check if the user is logged in
		user_id_cookie = self.request.cookies.get("user_id")
		if user_id_cookie:
			logged_user_id = int(user_id_cookie.split("|")[0])
			logged_user = User.get_by_id(logged_user_id)
		else:
			logged_user_id = None
			logged_user = None

		# If user is logged in and cookie is valid, render the new post page
		if user_id_cookie and check_secure_val(user_id_cookie):
			self.render("new_post.html", logged_user_id=logged_user_id)
		# If not, redirect to signup page
		else:
			self.redirect("/user_signup")

	def post(self):
		# Retrieve information submitted on the form
		subject = self.request.get("subject")
		content = self.request.get("content")

		# If a subject and content are present
		if subject and content:
			# Create a new post with the submitted information and with the
			# logged user information
			user_id_cookie = self.request.cookies.get("user_id")
			posted_by_id = int(user_id_cookie.split("|")[0])
			p = Post(subject = subject, content = content,
					 posted_by_id=posted_by_id)
			p.put()
			time.sleep(1)

			# Redirect to the post page
			self.redirect("/posts/"+str(p.key().id()))
		# Render the form again with an error message if subject and / or
		# content are not present
		else:
			error = "A subject and some content are required."
			self.render("new_post.html", subject=subject, content=content,
						error=error)

# Handler for showing posts
class ShowPostHandler(Handler):
	def get(self, blogpost_id):
		# Get current post and id of the poster; then, retrieve the user/poster
		current_post = Post.get_by_id(int(blogpost_id))
		user_id = current_post.posted_by_id
		user_poster = User.get_by_id(user_id)

		# Check if there's any permission error; if positive, define the
		# error message
		permission_error = ""
		if self.request.get("edit_permission") == "false":
			permission_error = "You do not have permission to edit this post."
		elif self.request.get("delete_permission") == "false":
			permission_error = "You do not have permission to delete this post."
		elif self.request.get("like_permission") == "false":
			permission_error = "Must be logged in to like a post."
		elif self.request.get("like_own") == "false":
			permission_error = "You can't like your own post or you already" + \
							   " liked that one"
		elif self.request.get("unlike_own") == "false":
			permission_error = "You can't unlike your own post or you" + \
							   " hadn't liked it before."
		elif self.request.get("comment_edit_permission") == "false":
			permission_error = "You don't have permission to edit that comment."

		# Calculate number of likes
		number_of_likes = str(len(current_post.likes))

		# Retrieve the logged user cookie
		user_id_cookie = self.request.cookies.get("user_id")
		if user_id_cookie:
			logged_user_id = int(user_id_cookie.split("|")[0])
		else:
			logged_user_id = None

		# Check if logged user already liked this post
		if logged_user_id in current_post.likes:
			liked = True
		else:
			liked = False

		# Retrieve comments for this post
		comments = Comment.all().filter('associated_post_id =',
										int(blogpost_id))

		# Render the template with the necessary information
		self.render("show_post.html", current_post=current_post,
					user_poster=user_poster, blogpost_id=blogpost_id,
					number_of_likes=number_of_likes, liked=liked,
					comments=comments, permission_error=permission_error,
					logged_user_id=logged_user_id)

	def post(self, blogpost_id):
		# Get current post and id of the poster; then, retrieve the user/poster
		current_post = Post.get_by_id(int(blogpost_id))
		user_id = current_post.posted_by_id
		user_poster = User.get_by_id(user_id)

		# Retrieve the logged user cookie
		user_id_cookie = self.request.cookies.get("user_id")
		if user_id_cookie:
			logged_user_id = int(user_id_cookie.split("|")[0])
		else:
			logged_user_id = None

		# Retrieve the content information
		content = self.request.get("content")

		# Calculate number of likes
		number_of_likes = str(len(current_post.likes))

		# Check if logged user already liked this post
		if logged_user_id in current_post.likes:
			liked = True
		else:
			liked = False

		# Retrieve comments for this post
		comments = Comment.all().filter('associated_post_id =',
										int(blogpost_id))

		# If content is present, create the comment with the provided
		# information and logged in user information
		if content:
			comment = Comment(associated_post_id = int(blogpost_id),
							  commenter = User.get_by_id(logged_user_id),
							  content = content)
			comment.put()
			time.sleep(1)
			self.redirect("/posts/" + blogpost_id)
		# If content is not present, set an error message and render the form
		# again with it.
		else:
			comment_error = "You need to write some content for your comment."
			self.render("show_post.html", current_post=current_post,
						user_poster=user_poster, blogpost_id=blogpost_id,
						number_of_likes=number_of_likes, liked=liked,
						comments=comments, comment_error=comment_error,
						logged_user_id=logged_user_id)

# Handler for editing posts
class EditPostHandler(Handler):
	def get(self, blogpost_id):
		# Retrieve the logged user cookie
		user_id_cookie = self.request.cookies.get("user_id")
		if user_id_cookie:
			logged_user_id = int(user_id_cookie.split("|")[0])
		else:
			logged_user_id = None

		# If user is logged in and is the poster of the post, render the edit
		# post form. If not, redirect to the post's page with error message.
		if user_id_cookie:
			user_id = int(user_id_cookie.split("|")[0])
			current_post = Post.get_by_id(int(blogpost_id))
			if current_post.posted_by_id == user_id:
				self.render("edit_post.html", current_post=current_post,
							logged_user_id=logged_user_id)
			else:
				self.redirect("/posts/" + blogpost_id +
							  "?edit_permission=false")
		else:
			self.redirect("/posts/" + blogpost_id + "?edit_permission=false")

	def post(self, blogpost_id):
		# Retrieve information submitted on the form
		subject = self.request.get("subject")
		content = self.request.get("content")
		# Retrieve the post
		current_post = Post.get_by_id(int(blogpost_id))
		# If subject and content are present, edit the post and save it
		if subject and content:
			post_id = int(self.request.get("post_id"))
			edited_post = Post.get_by_id(post_id)
			edited_post.subject = subject
			edited_post.content = content
			edited_post.put()
			time.sleep(1)
			self.redirect("/posts/" + blogpost_id)
		# If subject and / or content are not present, render the form again
		# with error message
		else:
			error = "A subject and some content are required."
			self.render("edit_post.html", current_post=current_post,
						subject=subject, content=content, error=error)

# Handler for deleting posts
class DeletePostHandler(Handler):
	def get(self, blogpost_id):
		# If user is logged in and is the poster of the post, delete the cookie
		# and redirect to main page
		user_id_cookie = self.request.cookies.get("user_id")
		if user_id_cookie:
			user_id_cookie = self.request.cookies.get("user_id")
			user_id = int(user_id_cookie.split("|")[0])
			current_post = Post.get_by_id(int(blogpost_id))
			if current_post.posted_by_id == user_id:
				current_post.delete()
				time.sleep(1)
				self.redirect("/")
			else:
				self.redirect("/posts/" + blogpost_id +
							  "?delete_permission=false")
		# If not, redirect user to the post's page with error message
		else:
			self.redirect("/posts/" + blogpost_id + "?delete_permission=false")

# Handler for liking posts
class LikePostHandler(Handler):
	def get(self, blogpost_id):
		# If user is logged in and is not the poster of the post, append its
		# ID to the list of likes of the post. If it's not, redirect to the
		# post's page with error message.
		user_id_cookie = self.request.cookies.get("user_id")
		if user_id_cookie:
			user_id_cookie = self.request.cookies.get("user_id")
			user_id = int(user_id_cookie.split("|")[0])
			current_post = Post.get_by_id(int(blogpost_id))
			if current_post.posted_by_id != user_id and \
				user_id not in current_post.likes:
				current_post.likes.append(user_id)
				current_post.put()
				time.sleep(1)
				self.redirect("/posts/" + blogpost_id)
			else:
				self.redirect("/posts/" + blogpost_id +
							  "?like_own=false")
		else:
			self.redirect("/posts/" + blogpost_id + "?like_permission=false")

# Handler for unliking posts
class UnlikePostHandler(Handler):
	def get(self, blogpost_id):
		# Check if user is logged in and if the user liked the post; if positive
		# unlike the post. If not, redirect to post's page with error message
		user_id_cookie = self.request.cookies.get("user_id")
		if user_id_cookie:
			user_id_cookie = self.request.cookies.get("user_id")
			user_id = int(user_id_cookie.split("|")[0])
			current_post = Post.get_by_id(int(blogpost_id))
			if current_post.posted_by_id != user_id and \
				user_id in current_post.likes:
				current_post.likes.remove(user_id)
				current_post.put()
				time.sleep(1)
				self.redirect("/posts/" + blogpost_id)
			else:
				self.redirect("/posts/" + blogpost_id +
							  "?unlike_own=false")
		else:
			self.redirect("/posts/" + blogpost_id)

# Handler for editing comments
class EditCommentHandler(Handler):
	def get(self, blogpost_id, comment_id):
		# Check if user is logged in and is the commenter of the comment. If
		# positive, render the edit comment form. If not, redirect to the post's
		# page with error message.
		user_id_cookie = self.request.cookies.get("user_id")
		if user_id_cookie:
			logged_user_id = int(user_id_cookie.split("|")[0])
			current_post = Post.get_by_id(int(blogpost_id))
			current_comment = Comment.get_by_id(int(comment_id))
			if current_comment.commenter.key().id() == logged_user_id:
				self.render("edit_comment.html",
							current_comment=current_comment,
							blogpost_id=blogpost_id, current_post=current_post,
							logged_user_id=logged_user_id)
			else:
				self.redirect("/posts/" + blogpost_id +
							  "?comment_edit_permission=false")
		else:
			self.redirect("/posts/" + blogpost_id +
						  "?comment_edit_permission=false")

	def post(self, blogpost_id, comment_id):
		# Check if user is logged in
		user_id_cookie = self.request.cookies.get("user_id")
		if user_id_cookie:
			logged_user_id = int(user_id_cookie.split("|")[0])

		# Retrieve the information submitted in the form
		content = self.request.get("content")
		current_comment = Comment.get_by_id(int(comment_id))
		current_post = Post.get_by_id(int(blogpost_id))
		# If content is provided, edit the comment and save it
		if content:
			current_comment.content = content
			current_comment.put()
			time.sleep(1)
			self.redirect("/posts/" + blogpost_id)
		# If not, render the edit comment again with error message
		else:
			comment_error = "Some content is required."
			self.render("edit_comment.html", current_comment=current_comment,
						comment_error=comment_error, current_post=current_post,
						logged_user_id=logged_user_id)

# Handler for deleting comments
class DeleteCommentHandler(Handler):
	def get(self, blogpost_id, comment_id):
		# Check if user is logged in
		user_id_cookie = self.request.cookies.get("user_id")
		# If user is logged in and user is the commenter of the comment, delete
		# the comment; if not, redirect to the post's page with error message
		if user_id_cookie:
			user_id_cookie = self.request.cookies.get("user_id")
			user_id = int(user_id_cookie.split("|")[0])
			current_comment = Comment.get_by_id(int(comment_id))
			if current_comment.commenter.key().id() == user_id:
				current_comment.delete()
				time.sleep(1)
				self.redirect("/posts/" + blogpost_id)
			else:
				self.redirect("/posts/" + blogpost_id +
							  "?comment_delete_permission=false")
		else:
			self.redirect("/posts/" + blogpost_id +
						  "?comment_delete_permission=false")

# Routes for the blog pages
app = webapp2.WSGIApplication([('/', MainPageHandler),
							   ('/new_post', NewPostHandler),
							   ('/user_signup', UserSignupHandler),
							   ('/welcome', WelcomeHandler),
							   ('/login', LoginHandler),
							   ('/logout', LogoutHandler),
							   ('/posts/(\d+)/edit', EditPostHandler),
							   ('/posts/(\d+)/delete', DeletePostHandler),
							   ('/posts/(\d+)/like', LikePostHandler),
							   ('/posts/(\d+)/unlike', UnlikePostHandler),
							   ('/posts/(\d+)/comments/(\d+)/delete',
							   		DeleteCommentHandler),
							   ('/posts/(\d+)/comments/(\d+)/edit',
							   		EditCommentHandler),
							   ('/posts/(\d+)', ShowPostHandler)],
							  debug=True)
