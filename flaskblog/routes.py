from flask import render_template, url_for, flash, redirect, request, abort
from flaskblog import app, db, bcrypt
from flaskblog.forms import RegistrationForm, LoginForm, UpdateAccountForm, PostForm, EditProfileForm, \
	AdminUserCreateForm, AdminUserUpdateForm, AddCommentForm
from flaskblog.models import User, Post, Todo, Comment
from flask_login import login_user, current_user, logout_user, login_required
import os
import errno
import secrets
from PIL import Image
from datetime import datetime
from flask_restful import Resource
import jwt
from functools import wraps
from flask import jsonify, request, Flask
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

def make_sure_path_exists(path):
    try:
        os.makedirs(path)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise

def save_picture(form_picture):
	random_hex = secrets.token_hex(8)
	f_name, f_ext = os.path.splitext(form_picture.filename)
	picture_fn = random_hex + f_ext
	path = os.path.join(app.root_path, 'static/profile_pics/'+current_user.username)
	make_sure_path_exists(path)
	picture_path = os.path.join(app.root_path, path, picture_fn)
	
	output_size = (125, 125)
	i = Image.open(form_picture)
	i.thumbnail(output_size)
	i.save(picture_path)

	return os.path.join(current_user.username,picture_fn)

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()

@app.route("/")
@app.route("/home")
def home():
	return render_template('home.html', title='Home')

@app.route("/services")
def services():
	return render_template('services.html', title='Services')

@app.route("/blog")
def blog():
	page = request.args.get('page', 1, type=int)
	posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
	return render_template('blog.html', posts=posts)

@app.route("/about")
def about():
	return render_template('about.html', title='About')

@app.route("/contact")
def contact_us():
	return render_template('contact.html', title='Contact')

def admin_login_required(func):
	@wraps(func)
	def decorated_view(*args, **kwargs):
		if not current_user.is_admin():
			return abort(403)
		return func(*args, **kwargs)
	return decorated_view

@app.route("/register", methods=['GET', 'POST'])
def register():
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	form = RegistrationForm()
	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		user = User(username=form.username.data, email=form.email.data, password=hashed_password)
		db.session.add(user)
		db.session.commit()
		flash('Your account has been created! You are now able to log in', 'success')
		return redirect(url_for('login'))
	return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user and bcrypt.check_password_hash(user.password, form.password.data):
			login_user(user, remember=form.remember.data)
			next_page = request.args.get('next')
			return redirect(next_page) if next_page else redirect(url_for('home'))
		else:
			flash('Login unsuccessful. Please check username and password', 'danger')
	return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
	logout_user()
	flash('You have been logged out.')
	return redirect(url_for('home'))

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
	page = request.args.get('page', 1, type=int)
	posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=20)
	form = UpdateAccountForm()
	if form.validate_on_submit():
		if form.picture.data:
			picture_file = save_picture(form.picture.data)
			current_user.image_file = picture_file
		current_user.username = form.username.data
		current_user.email = form.email.data
		current_user.about_me = form.about_me.data
		if bcrypt.check_password_hash(current_user.password, form.old_pass.data):
			hashed_password = bcrypt.generate_password_hash(form.new_pass.data).decode('utf-8')
			current_user.password = hashed_password
		else:
			flash('Old password is wrong!', 'danger')
			return redirect('account')
		db.session.commit()
		flash('Your account has been updated!', 'success')
		return redirect(url_for('account'))
	elif request.method == 'GET':
		form.username.data = current_user.username
		form.email.data = current_user.email
		form.about_me.data = current_user.about_me
	image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
	return render_template('account.html', title='Account', image_file=image_file, form=form, posts=posts)

@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter_by(user_id=user.id).paginate(page, 20, False)
    return render_template('user.html', user=user, posts=posts.items)

@app.route("/post/new", methods=['GET', 'POST'])
@login_required
@admin_login_required
def new_post():
	form = PostForm()
	if form.validate_on_submit():
		post = Post(title=form.title.data, content=form.content.data, author=current_user)
		db.session.add(post)
		db.session.commit()
		flash('Your post has been creared!', 'success')
		return redirect(url_for('blog'))
	return render_template('create_post.html', title='New Post', form=form, legend='New Post')

@app.route("/post/<int:post_id>")
def post(post_id):
	post = Post.query.get_or_404(post_id)
	comments = Comment.query.filter_by(post_id=post_id).all()
	form = AddCommentForm()
	comment_post(post_id)
	return render_template('post.html', title=post.title, post=post, form=form, comments=comments)

@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
@admin_login_required
def update_post(post_id):
	post = Post.query.get_or_404(post_id)
	if post.author != current_user:
		abort(403)
	form = PostForm()
	if form.validate_on_submit():
		post.title = form.title.data
		post.content = form.content.data
		db.session.commit()
		flash('Your post has been updated!', 'success')
		return redirect(url_for('post', post_id=post.id))
	elif request.method == 'GET':
		form.title.data = post.title
		form.content.data = post.content
	return render_template('create_post.html', title='Update Post', form=form, legend='Update Post')

@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
@admin_login_required
def delete_post(post_id):
	post = Post.query.get_or_404(post_id)
	if post.author != current_user:
		abort(403)
	db.session.delete(post)
	db.session.commit()
	flash('Your post has been deleted!', 'success')
	return redirect(url_for('blog'))

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
@login_required
def comment_post(post_id):
    post = Post.query.get_or_404(post_id)
    form = AddCommentForm()
    if form.validate_on_submit():
        comment = Comment(body=form.body.data, post_id=post_id, author=current_user)
        db.session.add(comment)
        db.session.commit()
        flash("Your comment has been added to the post", "success")
        return redirect(url_for("post", post_id=post.id))

@app.route('/like/<int:post_id>/<action>')
@login_required
def like_action(post_id, action):
    post = Post.query.filter_by(id=post_id).first_or_404()
    if action == 'like':
        current_user.like_post(post)
        db.session.commit()
    if action == 'unlike':
        current_user.unlike_post(post)
        db.session.commit()
    return redirect(request.referrer)

@app.route('/follow/<username>')
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} not found.'.format(username))
        return redirect(url_for('index'))
    if user == current_user:
        flash('You cannot follow yourself!')
        return redirect(url_for('user', username=username))
    current_user.follow(user)
    db.session.commit()
    flash('You are following {}!'.format(username))
    return redirect(url_for('user', username=username))


@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} not found.'.format(username))
        return redirect(url_for('index'))
    if user == current_user:
        flash('You cannot unfollow yourself!')
        return redirect(url_for('user', username=username))
    current_user.unfollow(user)
    db.session.commit()
    flash('You are not following {}.'.format(username))
    return redirect(url_for('user', username=username))

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
	form = EditProfileForm()
	if form.validate_on_submit():
		current_user.username = form.username.data
		current_user.about_me = form.about_me.data
		db.session.commit()
		flash('Your changes have been saved.')
		return redirect(url_for('edit_profile'))
	elif request.method == 'GET':
		form.username.data = current_user.username
		form.about_me.data = current_user.about_me
		return render_template('edit_profile.html', title='Edit Profile', form=form)

def admin_login_required(func):
	@wraps(func)
	def decorated_view(*args, **kwargs):
		if not current_user.is_admin():
			return abort(403)
		return func(*args, **kwargs)
	return decorated_view

@app.route('/admin')
@login_required
@admin_login_required
def home_admin():
	return render_template('admin-home.html')

@app.route('/admin/users-list')
@login_required
@admin_login_required
def users_list_admin():
	users = User.query.all()
	return render_template('users-list-admin.html', users=users)

@app.route('/admin/create-user', methods=['GET', 'POST'])
@login_required
@admin_login_required
def user_create_admin():
	form = AdminUserCreateForm(request.form)
	if form.validate():
		username = form.username.data
		password = form.password.data
		admin = form.admin.data
		existing_username = User.query.filter_by(username=username).first()
		if existing_username:
			flash('This username has been already taken. Try another one.','warning')
			return render_template('register.html', form=form)
		user = User(username, password, admin)
		db.session.add(user)
		db.session.commit()
		flash('New User Created.', 'info')
		return redirect(url_for('users_list_admin'))
		if form.errors:
			flash(form.errors, 'danger')
		return render_template('user-create-admin.html', form=form)

@app.route('/admin/update-user/<id>', methods=['GET', 'POST'])
@login_required
@admin_login_required
def user_update_admin(id):
	user = User.query.get(id)
	form = AdminUserUpdateForm(
		request.form,
		username=user.username,
		admin=user.admin)
	if form.validate():
		username = form.username.data
		admin = form.admin.data

		User.query.filter_by(id=id).update({
			'username': username,
			'admin': admin,})
		db.session.commit()
		flash('User Updated.', 'info')
		return redirect(url_for('users_list_admin'))
		if form.errors:
			flash(form.errors, 'danger')
			return render_template('user-update-admin.html', form=form, user=user)

@app.route('/admin/dalete-user/<id>')
@login_required
@admin_login_required
def user_delete_admin(id):
	user = User.query.get(id)
	user.delete()
	db.session.commit()
	flash('User Deleted.')
	return redirect(url_for('users_list_admin'))

'''class HelloView(BaseView):
    @expose('/')
    def index(self):
        return self.render('some-template.html')'''

'''class UserAdminView(ModelView, ActionsMixin):
    column_searchable_list = ('username',)
    column_sortable_list = ('username', 'admin')
    column_exclude_list = ('password',)
    form_excluded_columns = ('password',)
    form_edit_rules = ('username', 'admin',)
  
    def is_accessible(self):
        return current_user.is_authenticated() and current_user.is_admin()
    def scaffold_form(self):
        form_class = super(UserAdminView, self).scaffold_form()
        form_class.password = PasswordField('Password')
        return form_class
    def create_model(self, form):
        model = self.model(
            form.username.data, form.password.data, form.admin.data
        )
        form.populate_obj(model)
        self.session.add(model)
        self._on_model_change(form, model, True)
        self.session.commit()'''
"""@app.route("/api", methods=['GET', 'POST'])
def index():
    if (request.method =='POST'):
        some_json = request.get_json()
        return jsonify({'you sent': some_json}), 201
    else:
        return jsonify({"about": "Hello World!"})

@app.route('/multi/<int:num>', methods=['GET'])
def get_multiply10(num):
    return jsonify({'result': num*10})"""

class HelloWorld(Resource):
    def get(self):
        return {'about': 'Hello World!'}

    def post(self):
        some_json = request.get_json()
        return {'you sent': some_json}, 201

class Multi(Resource):
    def get(self, num):
        return {'result': num*10}

@app.route('/user', methods=['GET'])
def get_all_users():
	users = User.query.all()

	output=[]
	for user in users:
		user_data={}
		user_data['id'] = user.id
		user_data['name'] = user.name
		user_data['password'] = user.password
		user_data['admin'] = user.admin
		output.append(user_data)

	return jsonify({'users' : output})

@app.route('/users/<id>', methods=['GET'])
def get_one_user(id):
	user = User.query.filter_by(id=id).first()

	if not user:
		return jsonify({'message' : "No user found!"})

	user_data = {}
	user_data['id'] = user.id
	user_data['name'] = user.name
	user_data['password'] = user.password
	user_data['admin'] = user.admin

	return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
def create_user():
	# data = request.get_json()
	username = request.args.get('uesrname', '')
	email = request.args.get('email', '')
	password = request.args.get('password', 'sddsd')
	hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

	#new_user = User(id = id, username=username, email=email, password=hashed_password, admin=False)
	new_user = User(username=username, email=email, password=password, admin=False)
	db.session.add(new_user)
	db.session.commit()

	return jsonify({'message' : "New user created!"})

@app.route('/users/<id>', methods=['PUT'])
def promote_user(id):
	user = User.query.filter_by(id=id).first()

	if not user:
		return jsonify({'message' : "No user found!"})

	user.admin = True
	db.session.commit()
	return jsonify({'message' : "The user has been promoted!"})

@app.route('/users/<id>', methods=['DELETE'])
def delete_user(id):
	user = User.query.filter_by(id=id).first()

	if not user:
		return jsonify({'message' : "No user found!"})

	db.session.delete(user)
	db.session.commit()

	return jsonify({'message' : "The user has been deleted!"})