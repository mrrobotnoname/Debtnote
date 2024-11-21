from dotenv import load_dotenv
import os
import hashlib
from flask import Flask,render_template,redirect,request,url_for,session,flash,abort
import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Sequence

load_dotenv(override=True)
set_adminpass = os.getenv("set_adminpass")

app = Flask(__name__)
app.secret_key = os.getenv("secret_key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("database_url")
db = SQLAlchemy(app)



#######Database Model######
class User(db.Model):
    id = db.Column(db.Integer,Sequence('user_id-seq',start=0) ,primary_key=True)
    user = db.Column(db.String(50), unique = True, nullable = False)
    password = db.Column(db.CHAR(100), unique = True, nullable = False)
    user_level = db.Column(db.Integer, nullable = False)
    debt = db.Column(db.Float, nullable = False)
    flag = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.datetime.utcnow)

with app.app_context():
    db.create_all()

###Home page###
@app.route('/')
def index():
    if 'user' not in session or session['user'] is None:
        return redirect(url_for("login"))
    if session["user_level"] == 1:        
        return redirect(url_for('admin'))
    if session["user_level"] == 0:
        datas = User.query.filter_by(user = session["user"]).all()
        flash(f"{session['user']} Wellcome to Debt-Note",category="message")
        return render_template("user.html",datas=datas)

#Admin pannel
@app.route("/admin/")
def admin():
    if session.get("user_level",0) != 1:
        abort(401)
    
    datas = User.query.filter(User.user_level!=1).all()
    count = User.query.count()-1
    if request.args.get('search'):
        datas = User.query.filter_by(user = request.args.get('search')).filter(User.user_level!=1).all()
        if datas == []:
            flash("no user found!",category="error")
    return render_template("admin.html",datas=datas,count=count)

#Adding a user
@app.route("/admin/adduser/", methods = ["POST","GET"])
def adduser():
    if session.get("user_level",0) != 1:
        abort(401)

    if request.method == "POST":
        user = request.form.get("adduser")
        password = hashlib.md5(request.form["addpwd"].encode('utf-8')).hexdigest()
        checkuser = User.query.filter_by(user=user).first()
        checkpwd = User.query.filter_by(password=password).first()
        if checkuser is None:
            if checkpwd is None:
                add = User(user=user, password=password, user_level= 0, debt=0)
                db.session.add(add)
                db.session.commit()
                flash("New user has been created successfully!",category="message")
                return redirect(url_for("admin"))
            flash("This password has been taken,try deffrent one!",category="error")
            return redirect(url_for("adduser"))
        flash("This username has been taken,try deffrent one!",category="error")
        #return redirect(url_for("adduser"))
    return render_template("adduser.html")

#####################Edit User details#######################
@app.route('/admin/edituser/<int:id>',methods =["POST","GET"])
def edituser(id):
    if session['user_level'] is None or session["user_level"] != 1:
        abort(401)
    if id == 1:
        abort(404)
    datas =User.query.filter_by(id=id).first()
    if datas is None:
        flash("No user Found", category= "info")
        return redirect(url_for("admin"))    
    if request.method =="POST" and "action" in request.form:
        debt = request.form.get("debt")
        user= request.form.get("name")
        if request.form.get("password") is not None:
            password = hashlib.md5(request.form.get("password").encode('utf-8')).hexdigest()
            
        if request.form["action"] == "update_debt":
            print(type(request.form["action"]))
            try:
                if debt == f'-{debt}':
                    datas.debt -= debt
                datas.debt += float(debt)

                flash("Your Debt has been updated successfully.",category="message")
            except:
                flash("Wrong Format,Try again later!",category="erro")
        if request.form["action"] == "reset_debt":
            datas.debt = 0
            flash("Debt been clear!",category='message')
        if request.form["action"] == "update_user":
            check = User.query.filter_by(user=user).first()
            if check == None:        
                datas.user = user
                flash("Your username has been changed successfully.",category="message")
            else:
                flash("username allredy exsist",category="error")
        if request.form["action"] == "update_password":
            check = User.query.filter_by(password=password).first()
            if check is None:
                datas.password = password
                flash("Your passowrd has been changed successfully.",category="message")
            else:
                flash("This password allrady exsist",category="error")
        db.session.commit()
        if request.form["action"] == "delete_user":
            if request.form.get("delete") == datas.user:
                db.session.delete(datas)
                flash(f'{datas.user}\'s accouunt has been deleted successfully!',category="message")
                db.session.commit()
                remaining_users = User.query.filter(User.id > datas.id).all()
                for user in remaining_users:
                    user.id -=1
                db.session.commit()
                return redirect(url_for("admin"))
            flash("Wrong username,Plese try again!",category="error")
        return redirect(url_for("edituser", id = id))
    return render_template("edituser.html",datas=datas)
   
########################Login page######################
@app.route('/login', methods = ["POST", "GET"])
def login():

    if "user" in session and session["user"] is not None:
        return redirect(url_for("index"))
    
    if request.method == "POST":
        user = request.form["name"]
        password = hashlib.md5(request.form["password"].encode('utf-8')).hexdigest()
        data = User.query.filter_by(user=user).one_or_none()
        
        if data:
            if data.password == password:
                session["user"] = data.user
                session["user_level"] = data.user_level
                flash("Welcome To Debt Note",category="message")
                return redirect(url_for("index"))
                
            else:
                flash("Wrong password,Try again!",category="error")
        else:
            flash("Wrong username,Try again!",category="error")
        return redirect(url_for("login"))
        
    return render_template("login.html")

###################loguot####################
@app.route("/logout")
def logout():
    if 'user' in session :
        session["user"] = None
        session["user_level"] = None
        flash("Log out successfully!",category='message')
        return redirect(url_for("login"))
    
    return redirect(url_for("login"))

###############Admin install####################
@app.route('/install', methods = ["POST", "GET"])
def install():
    if request.method == "POST":
        if request.form["adminpass"] != set_adminpass:
            flash('Wrong password, try again', category="error")
            return redirect(url_for("install"))
        else:
            with app.app_context():
                db.drop_all(bind_key=None)
                db.create_all()

            admin_user = request.form["username"]
            password = hashlib.md5(request.form['password'].encode('utf-8')).hexdigest()
            add = User(user=admin_user,password = password, user_level= 1, debt= 0)
            db.session.add(add)
            db.session.commit()
            flash("Addmin has been added")
            return redirect(url_for("index"))    
        
    return render_template("install.html")

if __name__ == "__main__":
    app.run(debug="True")