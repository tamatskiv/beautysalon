from datetime import datetime
from flaskblog import db, login_manager, bcrypt
from flask_login import UserMixin
from hashlib import md5
from wtforms import BooleanField, widgets, TextAreaField

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

followers = db.Table('followers',
	db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
	db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

likers = db.Table('likers',
    db.Column('liker_id', db.Integer, db.ForeignKey('post.id')),
    db.Column('liked_id', db.Integer, db.ForeignKey('post.id'))
)

class User(db.Model, UserMixin):
	id = db.Column(db. Integer, primary_key=True)
	#public_id = db.Column(db.String(50), unique=True)
	name = db.Column(db.String(50))
	username = db.Column(db.String(20), unique=True, nullable=False)
	email = db.Column(db.String(120), unique=True, nullable=False)
	image_file = db.Column(db.String(20), nullable=False, default='default.jpg')																																																			
	password = db.Column(db.String(60), nullable=False)
	posts = db.relationship( 'Post', backref='author', lazy=True)
	comments = db.relationship('Comment', backref='author', lazy=True)
	about_me = db.Column(db.String(140))
	last_seen = db.Column(db.DateTime, default=datetime.utcnow)
	admin = db.Column(db.Boolean())
	notes = db.Column(db.UnicodeText)
	liked = db.relationship(
		'PostLike',foreign_keys='PostLike.user_id', backref='user', lazy='dynamic')
	followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')
	def __init__(self, username, email, password, notes='', admin=False):
		self.username = username
		self.email = email
		#self.password = bcrypt.generate_password_hash(password)
		self.password = password
		self.admin = admin
		self.notes = notes

	def is_admin(self):
		return self.admin
	
	def __repr__(self):
		return f"User('{self.username}', '{self.email}', '{self.image_file}')"

	def like_post(self, post):
		if not self.has_liked_post(post):
			like = PostLike(user_id=self.id, post_id=post.id)
			db.session.add(like)

	def unlike_post(self, post):
		if self.has_liked_post(post):
			PostLike.query.filter_by(
				user_id=self.id,
				post_id=post.id).delete()

	def has_liked_post(self, post):
		return PostLike.query.filter(
			PostLike.user_id == self.id,
			PostLike.post_id == post.id).count() > 0

	def avatar(self, size):
		digest = md5(self.email.lower().encode('utf-8')).hexdigest()
		return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(digest, size)

	def follow(self, user):
		if not self.is_following(user):
			self.followed.append(user)

	def unfollow(self, user):
		if self.is_following(user):
			self.followed.remove(user)

	def is_following(self, user):
		return self.followed.filter(
			followers.c.followed_id == user.id).count() > 0

	def followed_posts(self):
		followed = Post.query.join(
			followers, (followers.c.followed_id == Post.user_id)).filter(
				followers.c.follower_id == self.id)
		own = Post.query.filter_by(user_id=self.id)
		return followed.union(own).order_by(Post.timestamp.desc())

class Post(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(100), nullable=False)
	date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	content = db.Column(db.Text, nullable=False)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
	likes = db.relationship('PostLike', backref='post', lazy='dynamic')
	
	def __repr__(self):
		return f"Post('{self.title}', '{self.date_posted}')"

class CKTextAreaWidget(widgets.TextArea):
	def __call__(self, field, **kwargs):
		kwargs.setdefault('class_', 'ckeditor')
		return super(CKTextAreaWidget, self).__call__(field, **kwargs)

class CKTextAreaField(TextAreaField):
	widget = CKTextAreaWidget()

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Comment('{self.body}', '{self.timestamp}')"

class Todo(db.Model):
	id = db.Column(db. Integer, primary_key=True)
	text = db.Column(db.String(50))
	complete = db.Column(db.Boolean)
	user_id = db.Column(db.Integer)

class PostLike(db.Model):
    __tablename__ = 'post_like'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))