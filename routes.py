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

from sqlalchemy import func

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


@app.route('/')
def hello():
    if current_user.is_authenticated:
        return redirect('/home')
    return render_template('index.html',login=True)




# otp function
def find_otp():
    return randint(100000,999999)


#webmail taken page
@app.route('/otp_generator')
def otp_generator():
    return render_template('login_register/webmail.html')




#otp send and call otp_check page

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
            return render_template('login_register/otp_check.html',webmail=webmail)
        else:
            flash('Enter correct Webmail Id','danger')
    return redirect('/otp_generator')




#check otp correct or not and call register page

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
            return render_template('login_register/otp_check.html',webmail=webmail)
    return 




#student register page and call login

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
    return render_template('login_register/register.html',form=form,webmail=webmail)




#login page take credentials and sent to home

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
    return render_template('login_register/login.html',form=form)
    



#home page

@app.route('/home',methods=['GET','POST'])
@login_required
def home():
    P = Product.query.with_entities(Product.id).all()
    print(P)
    P.reverse()
    p=dict()
    for i in P:
        post=Product.query.filter_by(id=i[0]).first()
        if(post.rm==1):
            a=[]
            a.append(post.title)
            a.append(post.desc)
            a.append(post.price)
            pi=post.pic
            picname='uploads/'+pi
            p[picname]=a
    return render_template('pages/hm.html',prod=p)


#account page
@app.route('/account')
@login_required
def account():
    return render_template('pages/account.html',post=current_user)


#update profile

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        mobile = request.form['mobile']
        address = request.form['address']
        webmail = current_user.webmail  # Retrieve webmail from the hidden input field
        
        # Find the user by webmail
        user = User.query.filter_by(webmail=webmail).first()

        if user:
            # Update user profile information
            user.username = username
            user.mobile = mobile
            user.address = address
            
            # Commit changes to the database
            db.session.commit()
            
            return redirect(url_for('account'))  # Redirect to profile page or any other appropriate page
        else:
            return redirect(url_for('account'))  # Redirect to profile page or any other appropriate page



#logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('hello'))



#about page
@app.route('/about')
@login_required
def about():
    return render_template('pages/about.html')





# sell product page
@app.route('/sell')
@login_required
def upload():
    return render_template('pages/upload.html')


#upload product
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




#search form page
    
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
            if post.rm == 1:
                a = [post.title, post.desc, post.price]
                picname = f'uploads/{post.pic}'
                p[picname] = a
        l = len(p)
        return render_template('pages/searchres.html', prod=p, l=l, t=t)





#product details page
    
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
    
    return render_template('pages/details.html',t=a[0],p=a[1],u=a[2],c=a[3],d=a[4],e=a[5],des=a[6],pici=pic,ca=a[7],post=current_user)




#listed product by a user page

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

    return render_template('pages/list.html',prod=prod)
        



#remove product function
@app.route('/remove/<picid>',methods=['GET','POST'])
@login_required 
def remove(picid):
    p=Product.query.filter_by(pic=picid).first()
    db.session.delete(p)
    db.session.commit()
    return redirect(url_for('list'))






#feedback page
@app.route('/feedback')
@login_required
def feedback():
    return render_template('pages/feedback.html')

#feedback form submission function
@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    rating = int(request.form.get('rate'))
    comments = request.form.get('comments')

    feedback_entry = Feedback(rating=rating, comments=comments)
    db.session.add(feedback_entry)
    db.session.commit()

    return redirect(url_for('feedback'))






#admin_login page

@app.route('/admin_login')
def admin_login():
    if current_user.is_authenticated :
        return redirect('/admin_dashboard')
    return render_template('admin/admin_login.html')



#admin check function

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        webmail="ADMIN@nitt.edu"
        user=User.query.filter_by(webmail=webmail).first()
        password = request.form.get('password')
        if user and bcrypt.check_password_hash(user.password,password):
            login_user(user)
            return redirect('/admin_dashboard')
        else:
            flash('Please check Password','danger')
            return redirect('/admin_login')  
    return redirect('/admin_login')  





@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if  current_user.webmail.lower() != 'admin@nitt.edu':
        print("current_user : " +current_user)
        return redirect(url_for('admin_login'))  

    total_users = User.query.count()
    total_products = Product.query.count()
    total_feedbacks = Feedback.query.count()
    recent_feedbacks = Feedback.query.order_by(Feedback.id.desc()).limit(5).all()

    average_rating = calculate_average_rating()

    return render_template('admin/admin_page.html', 
                           total_users=total_users, 
                           total_products=total_products, 
                           total_feedbacks=total_feedbacks, 
                           recent_feedbacks=recent_feedbacks,
                           average_rating=average_rating)

def calculate_average_rating():
    average_rating = db.session.query(func.avg(Feedback.rating)).scalar()

    if average_rating:
        return round(average_rating, 1)  
    else:
        return 0.0


#user table 

@app.route('/user_table')
@login_required
def user_table():
    if current_user.webmail != 'ADMIN@nitt.edu':
        return redirect(url_for('admin_login'))  
    
    users = User.query.filter(User.webmail != 'ADMIN@nitt.edu').all()
    users.reverse()
    total_users = len(users)
    return render_template('admin/user_table.html', users=users, total_users=total_users)




#feedback table

@app.route('/feedback_table')
@login_required
def feedback_table():
    if current_user.webmail != 'ADMIN@nitt.edu':
        return redirect(url_for('admin_login')) 
    feedbacks = Feedback.query.all()
    total_feedbacks = Feedback.query.count()
    return render_template('admin/feedback_table.html', feedbacks=feedbacks, total_feedbacks=total_feedbacks) 



@app.route('/remove_feedback/<int:id>', methods=['GET', 'POST'])
@login_required 
def remove_feedback(id):
    if current_user.webmail.lower() != 'admin@nitt.edu':
        return redirect(url_for('admin_login'))  
    print(id)
    feedback = Feedback.query.filter_by(id=id).first()  
    feedback.reverse()
    db.session.delete(feedback)
    db.session.commit()
    return redirect(url_for('feedback_table'))

#product table

@app.route('/product_table')
@login_required
def product_table():
    if current_user.webmail != 'ADMIN@nitt.edu':
        return redirect(url_for('admin_login'))  
    products = Product.query.filter(Product.rm == 1).all()
    products.reverse()
    total_products = Product.query.count()
    return render_template('admin/product_table.html', products=products, total_products=total_products)


#pending products

@app.route('/pending_products')
@login_required
def pending_products():
    if current_user.webmail != 'ADMIN@nitt.edu':
        return redirect(url_for('admin_login'))  
    products = Product.query.filter(Product.rm == 0).all()
    products.reverse()
    total_products = Product.query.count()
    return render_template('admin/pending_products.html', products=products, total_products=total_products)


from flask import redirect, url_for

@app.route('/approve_product/<int:id>')
def approve_product(id):
    product = Product.query.get_or_404(id)
    product.rm = 1
    db.session.commit()
    return redirect(url_for('pending_products'))  # Redirect to a previous route after approval


#admin remove product function

@app.route('/remove_product/<id>',methods=['GET','POST'])
@login_required 
def remove_product(id):
    if current_user.webmail.lower() != 'admin@nitt.edu':
        return redirect(url_for('admin_login'))  
    p=Product.query.filter_by(id=id).first()
    print(id)
    db.session.delete(p)
    db.session.commit()
    return redirect(url_for('product_table'))





#admin remove user function

@app.route('/remove_user/<int:id>', methods=['GET', 'POST'])
@login_required 
def remove_user(id):
    if current_user.webmail.lower() != 'admin@nitt.edu':
        return redirect(url_for('admin_login'))  
    products = Product.query.filter_by(uid=id).all()
    for product in products:
        db.session.delete(product)
    
    user = User.query.get(id)
    if user:
        db.session.delete(user)
        db.session.commit()

    return redirect(url_for('user_table'))



#
#
#
# forget password routes
#
#
#

# take webmail
@app.route('/forgot_p')
def forgot_p():
    return render_template('forgot_password/forgot_web.html')




#sent otp
@app.route('/forgot_otp_validation',methods=['GET','POST'])
def forgot_otp_validation():
    if request.method=='POST':
        webmail=request.form['webmail']
        user=User.query.filter_by(webmail=webmail).first()
        global random_otp
        random_otp=find_otp()
        
        # print(random_otp)
        if(re.fullmatch(regex,webmail) or re.fullmatch(regex2,webmail)):
            msg = Message(
                'Password Reset OTP - NITT Exchange Hub',  # Subject for the email
                sender='sendotptowebmail@gmail.com',  # Sender's email address
                recipients=[webmail]  # Recipient's email address
            )

            # Generate and print the random OTP
            print(random_otp)

            # Customize the email body with the OTP and appropriate message for password reset
            msg.body = f"Hello,\n\nYou are receiving this email because you requested to reset your password on NITT Exchange Hub.\n\nTo complete the password reset process, please use the following OTP:\n\nYour OTP: {random_otp}\n\nIf you did not request a password reset, please ignore this email.\n\nThank you for using NITT Exchange Hub.\n\nBest regards,\nThe NITT Exchange Hub Team"

            mail.send(msg)
            return render_template('forgot_password/forgot_otp_validation.html',webmail=webmail)
        else:
            flash('Enter correct Webmail Id','danger')
    return redirect('/forgot_p')


#otp check and call change password page
@app.route('/forgot_otp_check',methods=['GET','POST'])
def forgot_otp_check():
    if request.method=='POST':
        user_otp=request.form['user_otp']
        webmail=request.form['webmail']
        print(user_otp)
        if(str(random_otp) == user_otp):
            return render_template('forgot_password/change_password.html', webmail=webmail)
        else:
            flash('Enter Correct OTP')
            return render_template('forgot_password/forgot_otp_validation.html',webmail=webmail)
    return 




# change password and then call login page
@app.route('/update_password', methods=['POST'])
def update_password():
    if request.method == 'POST':
        # Get the new password, confirm password, and webmail from the form
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        webmail = request.form['webmail']
        
        # Check if the passwords match
        if new_password != confirm_password:
            # Passwords do not match, flash a message and redirect back to the forgot password page
            flash('Passwords do not match. Please try again.', 'error')
            return render_template('forgot_password/change_password.html', webmail=webmail)
        
        # Find the user with the provided webmail
        user = User.query.filter_by(webmail=webmail).first()
        
        if user:
            # Update the user's password
            
            hashed_password=bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password=hashed_password  # Assuming you have a method set_password in your User model
            
            # Commit the changes to the database
            db.session.commit()
            
            # Flash a success message and redirect to the login page
            flash('Password updated successfully. You can now login with your new password.', 'success')
            return redirect(url_for('login'))
        else:
            # No user found with the provided webmail, flash an error message and redirect back to the forgot password page
            flash('No user found with the provided webmail.', 'error')
            return redirect(url_for('forgot_p'))