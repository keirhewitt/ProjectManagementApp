from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired, EqualTo
from .models import User, Room, Task

# ----------------------------------------------------------------------------
# Database entry Forms

# Logging into a Room
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

# Creating a Room
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

# Registering a User
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

    def validate_username(self, uname):
        existing_user_username = User.query.filter_by(
            username=uname.data).first()

        if not existing_user_username:
            raise ValidationError(
                "Invalid login details."
            )

# User Login forms
class LoginForm(FlaskForm):
    """User login"""
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20
    )], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20
    )], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")

    def validate_login(self, username):
        existing_user = User.query.filter_by(
            username=username.data).first()

        if not existing_user:
            raise ValidationError(
                "Invalid login details."
            )

# Create a Task form   
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

    description = TextAreaField(render_kw={"rows": 20}) # Not required for validation

    submit = SubmitField("Add Task")