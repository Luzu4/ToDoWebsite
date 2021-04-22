from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_login import login_user, LoginManager, current_user, UserMixin, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email
from werkzeug.security import generate_password_hash, check_password_hash
from flask_ckeditor import CKEditor
from sqlalchemy.orm import relationship
SECRET_KEY = 'tssss'

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
Bootstrap(app)
ckeditor = CKEditor(app)
login_manager = LoginManager()
login_manager.init_app(app)

app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    tasks = relationship('Task', back_populates="task_author")
    users_who_shared = db.Column(db.String(100))


class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    task_author = relationship('User', back_populates='tasks')
    text = db.Column(db.String(100))
    done = db.Column(db.Integer)
    progress = db.Column(db.Integer)


db.create_all()


class RegisterUser(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')


class LoginUser(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')


class UserTask(FlaskForm):
    task = StringField(validators=[DataRequired()], render_kw={"placeholder": "Add your Task Here"})


class ShareUser(FlaskForm):
    user_to_share = StringField(validators=[DataRequired()], render_kw={"placeholder": "Name of User"})


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route("/", methods=["POST", "GET"])
def home():
    current_user_id = current_user.get_id()
    return render_template("index.html", logged_in=current_user.is_authenticated, user_id=current_user_id)


@app.route("/list", methods=["POST", "GET"])
@login_required
def check_list():
    form = UserTask()
    if form.validate_on_submit():
        new_task = Task(
            text=form.task.data,
            task_author=current_user)
        db.session.add(new_task)
        db.session.commit()
    current_user_id = current_user.get_id()
    shared_ids = current_user.users_who_shared
    if shared_ids is not None:
        shared_ids = shared_ids.split()
    all_users = db.session.query(User).all()
    all_tasks = db.session.query(Task).all()
    form1 = ShareUser()

    if form1.validate_on_submit():
        shared_for_user = User.query.filter_by(name=form1.user_to_share.data).first()
        if shared_for_user.users_who_shared is not None:
            shared_for_user.users_who_shared = current_user_id + ' ' + shared_for_user.users_who_shared
        else:
            shared_for_user.users_who_shared = current_user_id
        db.session.commit()
    return render_template("check_list.html", form=form,
                           shared_ids=shared_ids,
                           form1=form1,
                           all_users=all_users,
                           user_id=current_user_id,
                           logged_in=current_user.is_authenticated,
                           all_tasks=all_tasks,
                           )


@app.route('/register_user', methods=["POST", "GET"])
def register_user():
    form = RegisterUser()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Mail Already Exist!')
            return render_template('register_user.html', form=form)
        else:
            new_user = User(
                name=form.name.data,
                email=form.email.data,
                password=generate_password_hash(form.password.data,
                                                method='pbkdf2:sha256',
                                                salt_length=8))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('check_list'))
    try:
        email = request.args['email']
        form.email.data = email
        return render_template('register_user.html', form=form, email=email)
    except KeyError:
        return render_template('register_user.html', form=form)


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginUser()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user is None:
            flash('PIIIIP, wrong mail!')
        else:
            if check_password_hash(user.password, password):
                login_user(user)
                flash('You are logged in!')
                return redirect(url_for('check_list'))
            else:
                flash('Wrong Password')
    return render_template("login_user.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/home_email', methods=["POST", "GET"])
def register_with_home_email():
    email = request.form['email']
    return redirect(url_for('register_user', email=email))


@app.route('/delete/<int:task_id>')
@login_required
def delete_task(task_id):
    task_to_delete = Task.query.get(task_id)
    db.session.delete(task_to_delete)
    db.session.commit()
    return redirect(url_for('check_list'))


@app.route('/complete_task/<int:task_id>')
@login_required
def complete_task(task_id):
    task_to_complete = Task.query.get(task_id)
    task_to_complete.done = 1
    db.session.commit()
    return redirect(url_for('check_list'))


@app.route('/in_progress_task/<int:task_id>')
@login_required
def in_progress_task(task_id):
    task_in_progress = Task.query.get(task_id)
    task_in_progress.progress = 1
    db.session.commit()
    return redirect(url_for('check_list'))


if __name__ == "__main__":
    app.run(debug=True)
