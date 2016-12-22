import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'blahblahblah'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Main handler of the blog
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        self.uid = self.read_secure_cookie('user_id')
        self.user = self.uid and User.by_id(int(self.uid))

    def loggedin_check(self):
        if not self.user:
            self.redirect("/login")
            return

class MainPage(BlogHandler):
    def get(self):
        self.write('Hello!')

# functions for hashing and password validations
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

# The user model.
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    # gets instance by the user id (uid)
    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = users_key())

    # gets instance by the name of user
    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    # returns User for registration in the model
    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    # validates user and password, returns user instance if success
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog key to be used for data storing.
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

# Post model - to store user posts data
class Post(db.Model):
    uid = db.StringProperty(required = True)
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    # renders a post and its data using the post.html template
    def render(self, uid):
        user = User.by_id(int(uid))
        self._render_text = self.content.replace('\n', '<br>')
        self._post_username = user.name
        self._no_of_likes = Like.get_by_post_id(str(self.key().id())).count()
        self._no_of_comments = Comment.get_by_post_id(str(self.key().id())).count()
        return render_str("post.html", p = self)

# Like model - to store likes of posts by users
class Like(db.Model):
    post_id = db.StringProperty(required = True)
    uid = db.StringProperty(required = True)

    # Get the like instances by post_id
    @classmethod
    def get_by_post_id(cls, post_id):
        q = cls.gql("WHERE post_id = :post_id", post_id = post_id)
        return q

    # Returns the instance if user liked the post
    @classmethod
    def user_liked(cls, post_id, uid=""):
        q = cls.gql("WHERE post_id = :post_id and uid = :uid", post_id = post_id, uid = uid)
        return q.get()

# Comment model - to store comments posted by user on a post
class Comment(db.Model):
    post_id = db.StringProperty(required = True)
    uid = db.StringProperty(required = True)
    comment = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    # Renders a comment by using the comment.html template
    def render(self, commenter_uid, uid):
        if uid == commenter_uid:
            self._by_user = True # returns True if commented by logged in user

        commenter = User.by_id(int(commenter_uid))
        self._render_text = self.comment.replace('\n', '<br>')
        self._commenter = commenter.name
        return render_str("comment.html", comment=self)

    # Returns the Comment instance by post_id
    @classmethod
    def get_by_post_id(cls, post_id):
        q = cls.gql("WHERE post_id = :post_id ORDER BY created DESC", post_id = post_id)
        return q

# Handler of the Blog Front Page - list all posts ordered by date created.
class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts)

# Handler of the post permalink page
class PostPage(BlogHandler):
    # to check if user is authorized to proceed by comparing user_id and the post associated user_id
    # returns the Post instance if true
    def user_auth(self, post_id):
        post = self.retrieve_post(post_id)
        if not post:
            self.error(404)
            return
        if self.uid == post.uid:
            return post

    def retrieve_post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        return post

    # To get post by post_id
    def get(self, post_id):
        comments = Comment.get_by_post_id(post_id) # gets associated comments
        posted_by_user = self.user_auth(post_id) # verified if the post is posted by currently logged in user

        post = self.retrieve_post(post_id) 
        if not post:
            self.error(404)
            return
        if Like.user_liked(post_id, self.uid): # Check if the logged in user liked the post
            like = "Unlike"
        else:
            like = "Like"

        params = dict(post = post,
                      like = like,
                      posted_by_user = posted_by_user,
                      comments = comments,
                      uid = self.uid)

        self.render("permalink.html", **params)

    # This post alters the like / unlike status
    def post(self, post_id):
        if not self.user:
            self.redirect("/login")
            return

        uid = self.uid
        
        post = self.retrieve_post(post_id)
        if not post:
            self.error(404)
            return
        
        posted_by_user = self.user_auth(post_id)

        if posted_by_user:
            self.render('forbidden.html')
            return

        user_liked = Like.user_liked(post_id, self.uid)

        if not user_liked:
            like = Like(parent = blog_key(), post_id = post_id, uid = uid)
            like.put()            
        else:
            user_liked.delete()
        
        self.redirect('/blog/%s' % post_id)
        
# Handler for posting new post
class NewPost(BlogHandler):
    # Renders the write post form
    def get(self):
        self.loggedin_check()

        self.render("writepost.html", newpost=True)

    # Submits the write post form
    def post(self):
        self.loggedin_check()

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), uid=self.uid, subject=subject, content=content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            params = dict(subject = subject,
                          content = content,
                          error = error,
                          newpost = True)            
            self.render("writepost.html", **params)

# Handler for editing post
class EditPost(PostPage):
    # Renders the write post form with stored subject and content
    def get(self, post_id):
        self.loggedin_check()

        post = self.user_auth(post_id)

        if not post:
            self.render('forbidden.html')
            return

        params = dict(subject = post.subject,
                      content = post.content,
                      post_id = post_id,
                      newpost = False)

        self.render("writepost.html", **params)
    # Submits the edited form
    def post(self, post_id):
        self.loggedin_check()

        subject = self.request.get('subject')
        content = self.request.get('content')
        post = self.user_auth(post_id)

        if subject and content:
        
            if not post:
                self.render('forbidden.html')
                return

            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "subject and content, please!"
            params = dict(subject = subject,
                      content = content,
                      post_id = post_id,
                      error = error,
                      newpost = False)

            self.render("writepost.html", **params)
# Handler to delete a post        
class DeletePost(PostPage):
    def get(self, post_id):
        self.loggedin_check()
        post = self.user_auth(post_id)
        if not post:
            self.render("forbidden.html")
            return

        self.render("delete.html", post_subject = post.subject)

    def post(self, post_id):
        self.loggedin_check()
        post = self.user_auth(post_id)
        if not post:
            self.render("forbidden.html")
            return
        likes = Like.get_by_post_id(post_id)
        post.delete()
        for like in likes:
            like.delete()
            
        self.redirect("/blog")

# Handler to post a new comment
class NewComment(BlogHandler):
    def get(self, post_id):
        self.loggedin_check()

        self.render("writecomment.html", newcomment=True)

    def post(self, post_id):
        self.loggedin_check()
        comment_text = self.request.get('comment')

        if comment_text:
            c = Comment(parent = blog_key(), post_id=post_id, uid=self.uid, comment=comment_text)
            c.put()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "leave a comment, please!"
            params = dict(comment_text=comment_text,
                          error=error,
                          newcomment=True)
            self.render("writecomment.html", **params)

# Handler to edit a comment
class EditComment(BlogHandler):
    # checks if the user is the commenter
    def commenter_auth(self, comment_id):
        comment = self.retrieve_comment(comment_id)
        if not comment:
            self.error(404)
            return
        if self.uid == comment.uid:
            return comment

    def retrieve_comment(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        comment = db.get(key)
        return comment

    def get(self, comment_id):
        self.loggedin_check()

        comment = self.commenter_auth(comment_id)
        comment_text = comment.comment

        if not comment:
            self.render('forbidden.html')
            return

        params = dict(comment_text = comment_text,
                      newcomment = False,
                      comment=comment)

        self.render("writecomment.html", **params)

    def post(self, comment_id):
        self.loggedin_check()
        comment_text = self.request.get('comment')
        comment = self.commenter_auth(comment_id)

        if comment_text:
            if not comment:
                self.render('forbidden.html')
                return
            comment.comment = comment_text
            comment.put()
            self.redirect('/blog/%s' % comment.post_id)
        else:
            error = "Leave a comment, please!"
            params = dict(comment_text = comment_text,
                      error = error,
                      newcomment = False,
                      comment=comment)

            self.render("writecomment.html", **params)

# Handler to delete a comment
class DeleteComment(EditComment):
    def get(self, comment_id):
        self.loggedin_check()

        comment = self.commenter_auth(comment_id)
        if not comment:
            self.render("forbidden.html")
            return

        self.render("delete-comment.html")

    def post(self, comment_id):
        self.loggedin_check()

        comment = self.commenter_auth(comment_id)
        if not comment:
            self.render("forbidden.html")
            return
        post_id = comment.post_id
        comment.delete()    
        self.redirect("/blog/" + post_id)    

# User data regex - for sign up 
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

# Sign up handler
class Signup(BlogHandler):
    def done(self, *a, **kw):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()
# Log in handler
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)
# Logout handler
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/edit/([0-9]+)', EditPost),
                               ('/blog/delete/([0-9]+)', DeletePost),
                               ('/blog/comment/([0-9]+)', NewComment),
                               ('/blog/ecomment/([0-9]+)', EditComment),
                               ('/blog/dcomment/([0-9]+)', DeleteComment),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
