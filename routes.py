from forms import RegistrationForm,LoginForm
from flask import render_template,flash,redirect,url_for,request
from app import db,bcrypt,app,User,Product, Feedback
from flask_login import current_user,login_required,logout_user,login_user
import os
from werkzeug.utils import secure_filename
from random import randint
from flask_mail import Mail,Message
import random
import re

regex = r'\b(\d+|[a-zA-Z]+)@nitt.edu\b'
regex2=r'^[a-z0-9](\.?[a-z0-9]){5,}@g(oogle)?mail\.com$'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif','webp'])

def allowed_file(filename):
 return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

mail = Mail(app) # instantiate the mail class
# configuration of mail
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'sendotptowebmail@gmail.com'
app.config['MAIL_PASSWORD'] = 'password'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

# 
def find_otp():
    return randint(100000,999999)

@app.route('/')
def hello():
    if current_user.is_authenticated:
        return redirect('/home')
    return render_template('index.html',login=True)


@app.route('/register/<string:webmail>',methods=['GET','POST'])
def register(webmail):
    form=RegistrationForm(request.form)
    if request.method=='POST' and form.validate():
          hashed_password=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
          user=User(username=form.userName.data,webmail=webmail,mobile=form.RollNo.data,address=form.address.data,course=form.course.data,password=hashed_password)
          db.session.add(user)
          db.session.commit()
          flash("Account created successfully ,you may login now!",'success')
          return redirect(url_for('login'))
    return render_template('register.html',form=form,webmail=webmail)

@app.route('/login',methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect('/home')    
    form=LoginForm(request.form)
    print("hello")
    if request.method=='POST' and form.validate():
        webmail=form.emailId.data
        print(webmail)
        user=User.query.filter_by(webmail=form.emailId.data).first()
        if user and bcrypt.check_password_hash(user.password,form.password.data):
            login_user(user,remember=form.remember.data)
            print(current_user.username)
            return redirect('/home')
        else:
            flash('Please check either Email or Password','danger')
    return render_template('login.html',form=form)
    


@app.route('/home',methods=['GET','POST'])
@login_required
def home():
    P=Product.query.with_entities(Product.id).all()
    P.reverse()
    p=dict()
    for i in P:
        post=Product.query.filter_by(id=i[0]).first()
        if(post.rm==0):
            a=[]
            a.append(post.title)
            a.append(post.desc)
            a.append(post.price)
            pi=post.pic
            picname='uploads/'+pi
            p[picname]=a
    return render_template('hm.html',prod=p)


@app.route('/otp_generator')
def otp_generator():
    return render_template('webmail.html')


@app.route('/validation',methods=['GET','POST'])
def validation():
    if request.method=='POST':
        webmail=request.form['webmail']
        user=User.query.filter_by(webmail=webmail).first()
        global random_otp
        random_otp=find_otp()
        
        # print(random_otp)
        if user is not None:
            flash('This Webmail Id already Exists')
        elif(re.fullmatch(regex,webmail) or re.fullmatch(regex2,webmail)):
            msg=Message(
                'Welcome to NITT Exchanage Hub',
                sender ='sendotptowebmail@gmail.com',
                recipients = [webmail]
               )
            print(random_otp)
            msg.body = f"Hello,\n\nWelcome to NITT EXCHANGE HUB! We're excited to have you on board.\n\nTo ensure the security of your account, we've generated a one-time password (OTP) for you. Please use the following OTP to complete your registration:\n\nYour OTP: {random_otp}\n\nIf you did not attempt to register on NITT EXCHANGE HUB, please ignore this email.\n\nThank you for choosing NITT EXCHANGE HUB. If you have any questions or need assistance, feel free to reach out to our support team at [sendotptowebmail@gmail.com].\n\nBest regards,\nThe NITT EXCHANGE HUB Team"
            mail.send(msg)
            return render_template('otp_check.html',webmail=webmail)
        else:
            flash('Enter correct Webmail Id','danger')
    return redirect('/otp_generator')

@app.route('/otp_validation',methods=['GET','POST'])
def otp_validation():
    if request.method=='POST':
        user_otp=request.form['user_otp']
        webmail=request.form['webmail']
        print(str(random_otp)==user_otp)
        print(random_otp)
        print(user_otp)
        if(str(random_otp) == user_otp):
            return redirect('/register/'+webmail)
        else:
            flash('Enter Correct OTP')
            return render_template('otp_check.html',webmail=webmail)
    return 

@app.route('/account')
@login_required
def account():
    return render_template('account.html',post=current_user)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('hello'))

@app.route('/sell')
@login_required
def upload():
    return render_template('upload.html')


@app.route('/about')
@login_required
def about():
    return render_template('about.html')


@app.route('/feedback')
@login_required
def feedback():
    return render_template('feedback.html')



@app.route('/uploader',methods=['GET','POST'])
@login_required
def uploader():
    file = request.files['photo']
    #name tag of form
    us_id = current_user.id
    description=request.form['descr']
    title=request.form['title']
    category=request.form['category']
    price=request.form['price']

    filename=str(us_id)+'.'+file.filename
    filename = secure_filename(filename)
  
    if file and allowed_file(file.filename):
       file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
  
       newFile = Product(uid=us_id,title=title,desc=description,cat=category,price=price,pic=filename)
       db.session.add(newFile)
       db.session.commit()
    #    flash('File successfully uploaded ' + file.filename + ' to the database!')

       return redirect(url_for('upload'))
    # else:
    #    flash('Invalid Uplaod only txt, pdf, png, jpg, jpeg, gif') 
    # return redirect(url_for('upload'))




@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'POST':
        t = random.random()
        sdata = request.form['search']
        data = f'%{sdata}%'
        P = Product.query.with_entities(Product.id).filter(Product.title.like(data)).all()
        P.reverse()
        p = {}
        for i in P:
            post = Product.query.filter_by(id=i[0]).first()
            if post.rm == 0:
                a = [post.title, post.desc, post.price]
                picname = f'uploads/{post.pic}'
                p[picname] = a
        l = len(p)
        return render_template('searchres.html', prod=p, l=l, t=t)


@app.route('/details/<picid>',methods=['GET','POST'])
@login_required 
def details(picid):
    p=Product.query.filter_by(pic=picid).first()
    uid=p.uid
    u=User.query.filter_by(id=uid).first()
    pic='uploads/'+picid
    a=[]
    a.append(p.title)
    a.append(p.price)
    a.append(u.username)
    a.append(u.course)
    a.append(u.address)
    a.append(u.mobile)
    a.append(p.desc)
    a.append(p.cat)
    
    return render_template('details.html',t=a[0],p=a[1],u=a[2],c=a[3],d=a[4],e=a[5],des=a[6],pici=pic,ca=a[7],post=current_user)


@app.route('/list')
@login_required
def list():
    ui=current_user.id
    p=Product.query.with_entities(Product.id).filter_by(uid=ui).all()
    prod=dict()
    for i in p:
        p1=Product.query.filter_by(id=i[0]).first()
        if(p1.rm==0):
            a=[]
            a.append(p1.title)
            a.append(p1.desc)
            a.append(p1.price)
            u=p1.pic
            picid='uploads/'+u
            prod[picid]=a

    return render_template('list.html',prod=prod)
        

@app.route('/remove/<picid>',methods=['GET','POST'])
@login_required 
def remove(picid):
    p=Product.query.filter_by(pic=picid).first()
    db.session.delete(p)
    db.session.commit()
    return redirect(url_for('list'))



@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    rating = int(request.form.get('rate'))
    comments = request.form.get('comments')

    feedback_entry = Feedback(rating=rating, comments=comments)
    db.session.add(feedback_entry)
    db.session.commit()

    return redirect(url_for('feedback'))

