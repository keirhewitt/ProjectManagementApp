from flask import Flask, flash, render_template, url_for, request, redirect
from flask_wtf.form import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired, EqualTo
from flask_bcrypt import Bcrypt
from datetime import datetime
import uuid


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = '!s£34f@C_332fvvbsd+'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

now = datetime.now()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -----------> DATABASE <------------ #

# Database table Room
class Room(db.Model):
    __tablename__ = 'room'
    key = db.Column(db.String(80), primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(60), nullable=False)
    task = relationship("Task")

# Database table Task
class Task(db.Model):
    __tablename__ = 'task'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), ForeignKey('room.key'))
    project = db.Column(db.String(100))
    job = db.Column(db.String(200))
    assignee = db.Column(db.String(40))
    progress = db.Column(db.String(200))
    description = db.Column(db.UnicodeText(), nullable=False)
    date = db.Column(db.String(30), default=now.strftime("%m/%d/%Y %H:%M"))

    def __repr__(self):
        return '<Task %r>' % self.id

# Database table User
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


# Database Forms
class RoomEntryForm(FlaskForm):
    """Logging into a Room using a room name and password"""
    room_name = StringField(validators=[InputRequired(),Length(
        min=4, max=80
    )], render_kw={"placeholder": "Room Name"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20
    )], render_kw={"placeholder": "Password"})

    submit = SubmitField("login")

    def validate_room(self, room_name):
        existing_room = Room.query.filter_by(
            name=room_name.data).first()

        if not existing_room:
            raise ValidationError("This room does not exist. Please enter a valid room.")

class RoomCreationForm(FlaskForm):
    """Creating a room object"""
    room_name = StringField(validators=[InputRequired(), Length(
        min=4, max=40
    )], render_kw={"placeholder": "Room name"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4)], render_kw={"placeholder": "Password"})

    confirm_pass = PasswordField(validators=[DataRequired('*Required'), 
    EqualTo('password', message='Password fields must match.'), Length(
        min=4)], render_kw={"placeholder": "Re-Enter Password"})

    submit = SubmitField("Create Room")

    def validate_room_creation(self, room_name):
        existing_room = Room.query.filter_by(
            room_key=room_name.first()
        )
        
        if existing_room:
            raise ValidationError("Room name already exists. Please use another name.")

class RegistrationForm(FlaskForm):
    """Form for registering a User (username/password)"""
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=40
    )], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4)], render_kw={"placeholder": "Password"})

    confirm_pass = PasswordField(validators=[DataRequired('*Required'), 
    EqualTo('password', message='Password fields must match.'), Length(
        min=4)], render_kw={"placeholder": "Re-Enter Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()

        if existing_user_username:
            raise ValidationError(
                "That username already exists. Please choose a different one."
            )

class LoginForm(FlaskForm):
    """User login"""
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20
    )], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20
    )], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")

    def validate_login(self, username, password):
        existing_user = User.query.filter_by(
            username=username.data).first()

        if not existing_user:
            raise ValidationError(
                "Invalid login details."
            )
        
class TaskCreationForm(FlaskForm):
    """Creating a Task for adding to database"""
    # Project, Job, Assignee, Stage
    project = StringField(validators=[InputRequired(), Length(
        min=1, max=60
    )], render_kw={"placeholder": "Project"})

    job = StringField(validators=[InputRequired(), Length(
        min=1, max=60
    )], render_kw={"placeholder": "Job"})

    assignee = StringField(validators=[InputRequired(), Length(
        min=1, max=60
    )], render_kw={"placeholder": "Assignee"})

    progress = StringField(validators=[InputRequired(), Length(
        min=1, max=60
    )], render_kw={"placeholder": "Progress"})

    description = TextAreaField(render_kw={"rows": 20})

    submit = SubmitField("Add Task")


# ----------------------------------------------------------------------------


# INDEX

# Index Page - Login to a room   
@app.route('/', methods=['GET','POST'])
@login_required
def index():
    form = RoomEntryForm()
    error = []
    if form.validate_on_submit():
        room = Room.query.filter_by(name=form.room_name.data).first()
        if room:
            if bcrypt.check_password_hash(room.password, form.password.data):
                flash("Room login accepted.", 'success')
                return redirect(url_for('room',room_name=room.name))
        error = "Invalid room credentials."
    rooms = Room.query.order_by(Room.name).all()
    return render_template('index.html', form=form, rooms=rooms, errors=error)


# ----------------------------------------------------------------------------

# ROOMS

# Display room logged in to
@app.route('/room/<string:room_name>', methods=['POST','GET'])
@login_required
def room(room_name):
    # Room contains a Task creation form and displays current Tasks active in current Room
    if request.method == 'POST':
        return redirect(url_for('create_task', room_name=room_name))
    room = Room.query.filter_by(name=room_name).first()
    tasks = Task.query.filter_by(key=room.key).order_by(Task.date).all()
    return render_template('room.html', tasks=tasks, roomname=room_name)

# App form for adding a Task to the given room
@app.route('/create/task/<string:room_name>', methods=['POST','GET'])
@login_required
def create_task(room_name):
    form = TaskCreationForm()
    room_key = Room.query.filter_by(name=room_name).first().key
    if form.validate_on_submit():
        new_task = Task(
            key         = room_key,
            project     = form.project.data,
            job         = form.job.data,
            assignee    = form.assignee.data,
            progress    = form.progress.data,
            description = form.description.data
        )
        try:
            db.session.add(new_task)
            db.session.commit()
            flash('Task added successfully.', 'success')
        except Exception:
            flash('There was an error adding the Task.', 'error')
        return redirect(url_for('room', room_name=room_name))
    return render_template('create-task.html', form=form)

# Creating a room
@app.route('/create/room', methods=['POST','GET'])
@login_required
def create_room():
    form = RoomCreationForm()

    if form.validate_on_submit(): 
        unique_room_key = str(uuid.uuid1().hex) # Create unique hex value for room_key
        hashed_password = bcrypt.generate_password_hash(form.password.data)  # Hash the password using Bcrypt
        new_room = Room(key=unique_room_key, name=form.room_name.data, password=hashed_password)
        db.session.add(new_room)
        db.session.commit()
        return redirect(url_for('index'))   # Redirect to index page on succesfull Room creation
    
    errors = [{'field': key, 'messages': form.errors[key]} for key in form.errors.keys()]
    return render_template('create-room.html',form=form,errors=errors)
        

# ----------------------------------------------------------------------------

# USERS
        
# User login
@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                # Login user using Flask login library
                login_user(user)
                return redirect(url_for('index'))
        flash('Invalid login credentials.', 'error')
        return redirect(url_for('login'))
    return render_template('login.html',form=form)

# User logout
@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    # Logout using Flask logout library
    logout_user()
    flash('User logged out.', 'info')
    return redirect(url_for('login'))

# Register user
@app.route('/register', methods=['GET','POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        # Hash users password using Bcrypt
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account creation succesful', 'success')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)


# ----------------------------------------------------------------------------

# Update/Delete Tasks 

# Delete Task item
@app.route('/delete/<int:id>')
@login_required
def delete(id):
    task_to_delete = Task.query.filter_by(id=id).first()
    room = Room.query.filter_by(key=task_to_delete.key).first().name

    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        flash('Task deleted successfully.', 'success')
        return redirect(url_for('room', room_name=room))
    except Exception:
        flash('There was an issue deleting the task.', 'info')
        return redirect(url_for('room', room_name=room))

# Update Task item
@app.route('/update/<int:id>', methods=['GET','POST'])
@login_required
def update(id):
    task_to_update = Task.query.filter_by(id=id).first()

    if request.method == 'POST':
        task_to_update.project = request.form['project']
        task_to_update.job = request.form['job']
        task_to_update.assignee = request.form['assignee']
        task_to_update.progress = request.form['progress']
        task_to_update.description = request.form['description']
        task_to_update.date = s1 = now.strftime("%m/%d/%Y %H:%M")
        try:
            db.session.commit()
            flash('Task updated successfully.', 'success')
            return redirect(url_for('room',room_name=Room.query.filter_by(key=task_to_update.key).first().name))
        except Exception:
            flash('There was an issue updating your task', 'info')
            return render_template('update.html', task=task_to_update)
    else:
        return render_template('update.html', task=task_to_update)


# ----------------------------------------------------------------------------


# Run app with debug
if __name__ == "__main__":
    app.run(debug=True)
