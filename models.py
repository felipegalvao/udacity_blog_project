from google.appengine.ext import db

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
