from flask_login import current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flaskblog.models import User, CKTextAreaField
from flask_admin.contrib.sqla import ModelView
from flask_admin.actions import ActionsMixin
from flask_admin import BaseView, expose, AdminIndexView
from flask_admin.form import rules
from flaskblog import bcrypt
from flask_ckeditor import CKEditor, CKEditorField

class RegistrationForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
	email = StringField('Email', validators=[DataRequired(), Email()])
	password = PasswordField('Password', validators=[DataRequired()])
	confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
	submit = SubmitField('Sign up')

	def validate_username(self, username):
		user = User.query.filter_by(username=username.data).first()
		if user:
			raise ValidationError('That username is taken. Please choose a differrent one')
	def validate_email(self, email):
		if User.query.filter_by(email=email.data).first():
			raise ValidationError('Email already registered.')

class LoginForm(FlaskForm):
	email = StringField('Email', validators=[DataRequired(), Email()])
	password = PasswordField('Password', validators=[DataRequired()])
	remember = BooleanField('Remember Me')
	submit = SubmitField('Login')

class UpdateAccountForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
	email = StringField('Email', validators=[DataRequired(), Email()])
	about_me = TextAreaField('About Me')
	picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
	old_pass = PasswordField('Old password', validators=[DataRequired()])
	new_pass = PasswordField('New password', validators=[DataRequired()])
	confirm_pass = PasswordField('Confirm password', validators=[DataRequired(), EqualTo('new_pass')])
	submit = SubmitField('Update')

	def validate_username(self, username):
		if username.data != current_user.username:
			user = User.query.filter_by(username=username.data).first()
			if user:
				raise ValidationError('That username is taken. Please choose a different one')

	def validate_email(self, email):
		if email.data != current_user.email:
			user = User.query.filter_by(email=email.data).first()
			if user:
				raise ValidationError('That email is taken. Please choose a different one')

class PostForm(FlaskForm):
	title = StringField('Title', validators=[DataRequired()])
	content = TextAreaField('Content', validators=[DataRequired()])
	submit = SubmitField('Post')

class EditProfileForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	about_me = TextAreaField('About me', validators=[Length(min=0, max=140)])
	submit = SubmitField('Submit')

class AdminUserCreateForm(FlaskForm):
	username = StringField('Username', [DataRequired()])
	password = PasswordField('Password', [DataRequired()])
	admin = BooleanField('Is Admin ?')

class AdminUserUpdateForm(FlaskForm):
	username = StringField('Username', [DataRequired()])
	admin = BooleanField('Is Admin ?')

'''class HelloView(BaseView):
    @expose('/')
    def index(self):
        return self.render('some-template.html')'''

class UserAdminView(ModelView, ActionsMixin):
    column_searchable_list = ('username',)
    column_sortable_list = ('username', 'admin')
    column_exclude_list = ('password',)
    form_excluded_columns = ('password',)
    form_edit_rules = ('username', 'admin',)
  
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin()

    def scaffold_form(self):
    	form_class = super(UserAdminView, self).scaffold_form()
    	form_class.password = PasswordField('Password')
    	form_class.new_password = PasswordField('New Password')
    	form_class.confirm = PasswordField('Confirm New Password')
    	return form_class

    def create_model(self, form):
        model = self.model(
            form.username.data, form.password.data, form.admin.data
        )
        form.populate_obj(model)
        model.password = bcrypt.generate_password_hash(form.password.data)
        self.session.add(model)
        self._on_model_change(form, model, True)
        self.session.commit()

    form_edit_rules = ('username', 'admin', 'notes', rules.Header('Reset Password'),'new_password', 'confirm')
    form_create_rules = ('username', 'admin', 'email', 'notes', 'password')

    form_overrides = dict(notes=CKTextAreaField)
    create_template = 'edit.html'
    edit_template = 'edit.html'

    def update_model(self, form, model):
    	form.populate_obj(model)
    	if form.new_password.data:
    		if form.new_password.data != form.confirm.data:
    			flash('Passwords must match')
    			return
    		model.password = bcrypt.generate_password_hash(form.new_password.data)
    	self.session.add(model)
    	self._on_model_change(form, model, False)
    	self.session.commit()