from flask import Flask, render_template, url_for, request, redirect
from flask_wtf.form import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = '!s£34f@C_332fvvbsd+'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20
    )], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20
    )], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()

        if existing_user_username:
            raise ValidationError(
                "That username already exists. Please choose a different one."
            )

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20
    )], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20
    )], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")
        
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        
            

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project = db.Column(db.String(100))
    job = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(40),nullable=False)
    stage = db.Column(db.String(100))
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return '<Task %r>' % self.id


@app.route('/', methods=['POST','GET'])
def index():
    if request.method == 'POST':
        task_project = request.form['project']
        task_job = request.form['job']
        task_name = request.form['name']
        task_stage = request.form['stage']
        new_task = Task(project=task_project,job=task_job,name=task_name,stage=task_stage)

        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect('/')
        except:
            return 'There was an issue adding your task'

    else:
        tasks = Task.query.order_by(Task.date).all()
        return render_template('index.html', tasks=tasks)

@app.route('/dashboard', methods=['POST','GET'])
def dashboard():
    return render_template('dashboard.html')

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('index'))
    return render_template('login.html',form=form)

@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET','POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html',form=form)
   


@app.route('/delete/<int:id>')
def delete(id):
    task_to_delete = Task.query.get_or_404(id)

    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect('/')
    except:
        return 'There was a problem deleting that task'

@app.route('/update/<int:id>', methods=['GET','POST'])
def update(id):
    task = Task.query.get_or_404(id)

    if request.method == 'POST':
        task.project = request.form['project']
        task.job = request.form['job']
        task.name = request.form['name']
        task.stage = request.form['stage']
        task.date = datetime.utcnow
        try:
            db.session.commit()
            return redirect('/')
        except:
            return 'There was an issue updating your task'
    else:
        return render_template('update.html',task=task)

if __name__ == "__main__":
    app.run(debug=True)
