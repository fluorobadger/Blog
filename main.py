from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request, get_flashed_messages
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from typing import List
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import requests
import smtplib
import os

my_gmail = os.environ.get('MY_GMAIL')
g_pass = os.environ.get('MY_GPASS')
g_smtp = os.environ.get('MY_SMTP')
my_email = os.environ.get('MY_EMAIL')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None
                    )


def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            if current_user.id == 1:
                return function(*args, **kwargs)
            else:
                flash("You must be an admin to access this area")
                return redirect(url_for('login'))
        except AttributeError:
            flash("You must be logged in to access this area")
            return redirect(url_for('login'))
    return wrapper

# CREATE DATABASE
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()
login_manager.init_app(app)
db.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author = relationship("User", back_populates="blog_posts")
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    comments: Mapped[List["Comment"]] = relationship("Comment", back_populates="blog_post")
    
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    email: Mapped[str] = mapped_column(String(250), nullable=False, unique=True)
    password: Mapped[str] = mapped_column(String(1000), nullable=False)
    blog_posts: Mapped[List["BlogPost"]] = relationship("BlogPost", back_populates="author")
    user_comments: Mapped[List["Comment"]] = relationship("Comment", back_populates="comment_author")

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    comment_author = relationship("User", back_populates="user_comments")
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    blog_post = relationship("BlogPost", back_populates="comments")
    post_id: Mapped[int] = mapped_column(Integer, ForeignKey("blog_posts.id"))

with app.app_context():
    db.create_all()


@app.route('/register', methods=["GET","POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hash = generate_password_hash(password=form.password.data, method = 'pbkdf2', salt_length = 8)
        new_user = User(name=form.name.data, email=form.email.data, password= hash)
        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("This email is already registered. Please login instead")
            return redirect(url_for("login"))
        else:
            login_user(new_user)
            flash("Logged in successfully")
            next = request.args.get('next')
            return redirect(next or url_for('get_all_posts'))
    return render_template("register.html", form = form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods = ["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        try:
            requested_user = User.query.filter_by(email=email).one()
        except NoResultFound:
            db.session.rollback()
            flash("No user was found under this email. Please try again")
            return render_template("login.html", form=form)
        else:
            if check_password_hash(requested_user.password, password):
                login_user(requested_user)
                flash("Logged in successfully")
                next = request.args.get('next')
                return redirect(next or url_for('get_all_posts'))
            else:
                db.session.rollback()
                flash("Incorrect password. Please try again.")
                return render_template("login.html", form=form, email=email)
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    flash("Logged out successfully")
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    messages= get_flashed_messages()
    print(messages)
    return render_template("index.html", all_posts=posts, messages=messages)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET","POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(text = form.comment.data, comment_author = current_user, blog_post = requested_post)
            db.session.add(new_comment)
            db.session.commit()
            return redirect (url_for('show_post', post_id = requested_post.id))
        else:
            flash("You need to login to comment")
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, form=form)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"], endpoint='add_new_post')
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"], endpoint='edit_post')
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>", methods=["GET","POST"], endpoint='delete_post')
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET","POST"])
def contact():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        phone = request.form["phone"]
        message = request.form["message"]
        final_message = f"Name: {name}\nEmail: {email}\nPhone: {phone}\nMessage: {message}"
        with smtplib.SMTP(g_smtp, port=587) as connection:
            connection.starttls()
            connection.login(user = my_gmail, password = g_pass)
            connection.sendmail(from_addr=my_gmail, 
                                to_addrs=my_email, 
                                msg=f"Subject: Message from Contact Form\n\n{final_message}")   
        flash("Message sent successfully")    
        return redirect(url_for("get_all_posts"))
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=False, port=5002)
