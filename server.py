from flask import Flask
from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask import request
from markupsafe import escape

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = 'xDW0[G8lMyBqx~1}27-T<[|<"7qlyb'
Bootstrap(app)

class LoginForm(FlaskForm):
    loginid = StringField('Login ID', validators=[DataRequired()])
    password = PasswordField('Password',validators=[DataRequired()])
    submit = SubmitField()

def get_static_file(filename):
    return url_for('static', filename=filename)

@app.route('/main')
def index():
    return render_template('login.html',name="keir",message="Temp message")


@app.route('/home/<int:id>')
def home(you):
    return render_template('index.html', name=you, message="message<TEMP")


@app.route('/', methods=['GET','POST'])
def login():
    names = ['keir','test']
    form = LoginForm()

    message = ""
    if form.validate_on_submit():
        loginid = form.loginid.data
        if loginid.lower() in names:
            form.loginid.data = ""
            id = loginid

            return redirect(url_for('home',id=id))
        else:
            message = "Incorrect login"
    return render_template('index.html')

with app.test_request_context('/hello',method='POST'):
    assert request.path == '/hello'
    assert request.method == 'POST'
    

if __name__ == '__main__':
    app.run(host='localhost', port=5000)