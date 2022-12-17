from core import app, login_manager
from core.models import db, User, Task, Room
from flask import flash, render_template, url_for, request, redirect
from flask_bcrypt import Bcrypt
from flask_login import login_user, login_required, logout_user, current_user
from core.forms import RoomEntryForm, RoomCreationForm, TaskCreationForm, LoginForm, RegistrationForm
from datetime import datetime
import uuid

now = datetime.now()
bcrypt = Bcrypt(app) # Initialise Bcrypt for hashing

# Intialise user_loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------------------------------------------------------------------
# Home page

# Index Page - Login to a room   
@app.route('/', methods=['GET','POST'])
@login_required
def index():
    form = RoomEntryForm()
    error = []
    if form.validate_on_submit():
        room = Room.query.filter_by(name=form.room_name.data).first()   # Find the room given in the form, by name
        if room:    # If the room exists
            if bcrypt.check_password_hash(room.password, form.password.data):   # Check the password
                flash("Room login accepted.", 'success')
                return redirect(url_for('room',room_name=room.name))    # Redirect to the room page if valid login
        flash('Invalid rooms credentials.', 'error')
    rooms = Room.query.order_by(Room.name).all()    # Get all rooms
    return render_template('index.html', form=form, rooms=rooms, errors=error) # Render main page with a list of all current rooms


# ----------------------------------------------------------------------------
# Rooms

# Display room logged in to
@app.route('/room/<string:room_name>', methods=['POST','GET'])
@login_required
def room(room_name):
    # Room contains a Task creation form and displays current Tasks active in current Room
    if request.method == 'POST':
        return redirect(url_for('create_task', room_name=room_name))    # Task creation sends POST request, navigate to the page
    room = Room.query.filter_by(name=room_name).first()
    tasks = Task.query.filter_by(key=room.key).order_by(Task.date).all()
    return render_template('room.html', tasks=tasks, roomname=room_name)    # Display current room tasks and name

# Create Task for Room
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
            db.session.add(new_task)    # Add the task to the database
            db.session.commit()
            flash('Task added successfully.', 'success')    # Show success message on successful database commit
        except Exception:
            flash('There was an error adding the Task.', 'error')   # Database commit error
        return redirect(url_for('room', room_name=room_name))   # Redirect to the room after trying to add task
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
        return redirect(url_for('index'))   # Redirect to index page on successful Room creation
    
    errors = [{'field': key, 'messages': form.errors[key]} for key in form.errors.keys()]
    return render_template('create-room.html',form=form,errors=errors)
        

# ----------------------------------------------------------------------------
# Users
        
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
        flash('Invalid login credentials.', 'error')    # On form validation error
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
        if form.validate_username(form.username):
            hashed_password = bcrypt.generate_password_hash(form.password.data)     # Hash the password using BCrypt
            new_user = User(username=form.username.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account creation succesful', 'success')
            return redirect(url_for('login'))   # Redirect to login page on successful registration
        else:
            flash('Username already exists, please enter a new one.', 'info')
            return redirect(url_for('register'))
    return render_template('register.html',form=form)


# ----------------------------------------------------------------------------
# Handle Unauthorised users

@login_manager.unauthorized_handler
def unauthorized_callback():            # In call back url we can specify where we want to 
    flash('You must be logged in for access to that.', 'error')
    return redirect(url_for('login'))

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
        task_to_update.project      = request.form['project']
        task_to_update.job          = request.form['job']
        task_to_update.assignee     = request.form['assignee']
        task_to_update.progress     = request.form['progress']
        task_to_update.description  = request.form['description']
        task_to_update.date = s1    = now.strftime("%m/%d/%Y %H:%M")
        try:
            db.session.commit()
            flash('Task updated successfully.', 'success')
            return redirect(url_for('room',room_name=Room.query.filter_by(key=task_to_update.key).first().name))
        except Exception:
            flash('There was an issue updating your task', 'info')
            return render_template('update.html', task=task_to_update)
    else:
        return render_template('update.html', task=task_to_update)
