from flask import Flask,request,flash,get_flashed_messages,render_template_string
from utils import generate_otp,my_gmail_password
from test1 import landing_page,otp_page
import json
import re
import bcrypt
import smtplib

app = Flask(__name__)

class User():
   def __init__(self):
      self.email = None
      self.password = None
      self.otp = None

user = User()

# Method to return json object
@app.route('/jsonpage',methods=['POST'])
def jsonfun():
    print(request.args.get("jsonobj"))
    return json.dumps(request.args.get("jsonobj"))


# app starts here
@app.route('/')
@app.route('/login',)
def login():
    return render_template_string(landing_page)

@app.route('/authenticate',methods=['GET','POST'])
def check_login_or_signup():
   if 'login' in list(request.form.keys()):
      email = request.form['email']
      password = request.form['password']
      with open('users.json','r') as f:
         users = json.load(f)
         
      
      if email in users.keys():

         salt = bytes(users[email].split('\t')[1][2:-1],'utf-8')
         password = bytes(password,'utf-8')
         hashed = bcrypt.hashpw(password, salt)

         
         

         if str(hashed) == users[email].split('\t')[0]:
            flash("Login succesfful")
            return render_template_string(landing_page)
         else:
            flash("Login failed,password mismatch")
            return render_template_string(landing_page)
      else:
         flash("Login failed,email not found")
         return render_template_string(landing_page)
   else:
      email = request.form['email']
      password = request.form['password']
      user.email = email
      user.password = password
      if (bool(re.match("(^[a-z])([a-z0-9]+)@gmail\.com",email))) and (bool(re.compile('[A-Z]+').search(password)) and bool(re.compile('[a-z]+').search(password)) and bool(re.compile('[0-9]+').search(password)) and bool(re.compile('[!@#$%^&*=-]+').search(password))):
         # SMTP Code here 
         user.otp = generate_otp()
         s=smtplib.SMTP('smtp.gmail.com',587)
         s.starttls()
         s.login('amaanrahil29@gmail.com',my_gmail_password)
         msg="OTP generated is "+str(user.otp)
         s.sendmail("amaanrahil29@gmail.com","amaanrahil29@gmail.com",msg)
         s.quit()

         # -------------
         
         
         return otp_page
      else:
         flash("Invalid email or password")
         return render_template_string(landing_page)
        


@app.route('/checkotp',methods=['GET','POST'])
def checkotp():
   entered_otp = request.form['entered_otp']
   if user.otp==int(entered_otp):
      salt = bcrypt.gensalt()
      password = bytes(user.password,'utf-8')
      hashed = bcrypt.hashpw(password, salt)

      with open("users.json","r") as f:
         users = json.load(f)

      users[user.email] = str(hashed)+'\t'+str(salt)

      with open('users.json','w+') as f:
         json.dump(users,f)

      flash("Sign up successful")
      return render_template_string(landing_page)
   else:
      flash("otp failed")
      return render_template_string(landing_page)


if __name__=="__main__":
   app.secret_key = 'super secret key'
   app.config['SESSION_TYPE'] = 'filesystem'

   
   app.run(debug=True)