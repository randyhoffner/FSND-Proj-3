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

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


secret = '6R%=[`OG|G)9'


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)



##### user stuff
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


##Facilitates multiple blogs, and selects this particular blog as "default".
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)


##Models##
##"User" model
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##"Post" model
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    author = db.StringProperty(User)
    last_modified = db.DateTimeProperty(auto_now = True)
    created_by = db.TextProperty()
    user_id = db.IntegerProperty(required = True)
    likes = db.IntegerProperty(default = 0)
    liked_by = db.ListProperty(str)

    @classmethod
    def by_post_name(cls, name):
      u = cls.all().filter('name=', name).get()
      return u

    @classmethod
    def by_name(cls, name):
      u = db.GqlQuery('select * from User where name=name')
      return u

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

    @property
    def comments(self):
        return Comment.all().filter('post_id = ', int(self.key().id()))


##"Like" model
class Like(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name


##"Comment" model
class Comment(db.Model):
    user_id = db.IntegerProperty(required = True)
    post_id = db.IntegerProperty(required = True)
    comment = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name


##Handlers##
##"BlogHandler".  (a)logs in user and sets a secure cookie; (b)logs user out; (c)initializes RequestHandler.
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
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


##"MainPage" handler.  Opens main page and directs user to blog page.
class MainPage(BlogHandler):
  def get(self):
      self.write("Hello, and welcome to Randy's Blog.  To get started, add /blog to the url.")


##"BlogFront" handler.  Renders blog front page, including last 10 posts in descending order by time.  Also renders "signup", "login", and "New Post" links.
class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery('select * from Post order by created desc limit 10')
        self.render('front.html', posts = posts)


##"PostPage" handler.  Ensures (a)that poster is legitimate; (b)that a post actually exists.  Renders permalink.html, the page containing the single post.
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        self.render('permalink.html', post = post)


##"NewPost" handler.  Ensures that (a)the poster is logged in; (b)that the post belongs ##to the logged-in individual; (c)that the post contains a subject and some ##content.
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render('newpost.html')
        else:
            self.redirect('/login')

    def post(self):
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, created_by = self.user.name, user_id = self.user.key().id())
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render('newpost.html', subject=subject, content=content, error=error)


##"LikePost" handler.  Ensure that (a)the liker is logged in; (b)the liker is not the author of the post; (c)the liker only likes the post once, by adding the liker to a list of likers.  Increments the number of "Likes".
class LikePost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect("/login?error=You must be logged in to Like a post")
        else:
            key= db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                return self.redirect('/blog')
            author = post.created_by
            current_user = self.user.name

            if author == current_user or current_user in post.liked_by:
                self.redirect("/blog?error=Cannot Like your own post; you may only Like a post once.")
            else:
                post.likes=post.likes + 1
                post.liked_by.append(current_user)
                post.put()
                self.redirect('/blog')


##"UnlikePost" handler:  Ensure that (a)the unliker does not own the post; (b)the ##unliker has not already unliked the post. Decrement the number of likes, and remover the unliker from the list of likers.
class UnlikePost(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
          return self.redirect('blog')
        author = post.created_by
        current_user = self.user.name

        if author and self.user.key().id() == post.user_id:
                self.redirect("/blog?error=Cannot unlike your own post.")
        elif post.likes <= 0:
            self.redirect("/blog?error=Cannot unlike this post again.")
        else:
            l = Like.all().filter('user_id=', self.user.key().id()).filter('post_id =', post.key().id()).get

            if l:
                post.likes -= 1

                post.liked_by.remove(current_user)
                post.put()

                self.redirect('/blog')


##"New Comment" handler.  Ensures that (a)the commenter is logged in; (b)the post exists.  Renders newcomment.html page.  If comment exists and is legitimate, renders updated permalink.html page.
class NewComment(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
            return
        post = Post.get_by_id(int(post_id), parent=blog_key())
        if not post:
          return self.redirect('blog')
        subject = post.subject
        content = post.content
        self.render('newcomment.html', subject=subject, content=content, pkey=post.key())

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        if not self.user:
            return self.redirect('/login')
        comment = self.request.get('comment')
        if comment:
            c = Comment(comment=comment, post_id=int(post_id), user_id=self.user.key().id())
            c.put()
            self.redirect('/blog/%s' % str(post_id))
        else:
            error = "Comment Required"
            self.render('permalink.html', post=post, error=error)


##"EditComment" handler.  Ensures that comment editor is logged in; (b)that the ##comment actually exists; (c)that the comment editor owns the comment.  Renders ##editcomment.html page.  Ensures that the editcomment.html page contains ##information.  Updates comment.
class EditComment(BlogHandler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        if not comment:
          return self.redirect('blog')
        if not self.user:
            self.redirect('/login')
        elif comment.user_id == self.user.key().id():

            self.render('editcomment.html', comment=comment, post=comment)
        else:
            return self.redirect("/blog?error=You may edit only your own comment.")

    def post(self, comment_id):
      if self.user:
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        if not comment:
          return self.redirect('/blog')

        if comment.user_id != self.user.key().id():
          return self.redirect ("/blog?error=You may edit only your own comment.")

        content = self.request.get('comment')
        if not content:
          return self.redirect('/blog/editcomment/%s' % str(comment.key().id()))
        comment.comment = content
        comment.put()
        self.redirect('/blog')
      else:
        return self.redirect('/login')


##"DeleteComment" handler.  Ensures that (a)comment deleter is logged in; (b)comment deleter actually owns the comment.  Renders deletecomment.html page. Deletes comment and returns to '/blog' page.
class DeleteComment(BlogHandler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        if not comment:
          return self.redirect('blog')

        if not self.user:
            return self.redirect('/login')
        elif comment.user_id == self.user.key().id():
            self.render('deletecomment.html', comment=comment, post=comment)
        else:
            return self.redirect("/blog?error=You may delete only your own comment")

    def post(self, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)

            if comment.user_id != self.user.key().id():
                return self.redirect('/blog')

            comment.delete()
            self.redirect('/blog')
        else:
            return self.redirect('/login')


##"DeletePost" handler.  Ensures (a)deleter is logged in; (b)deleter owns the post.  Deletes post and returns to '/blog' page.
class DeletePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
          return self.redirect('blog')
        if not self.user:
            return self.redirect('/login')
        elif post.user_id == self.user.key().id():
            self.render('deletepost.html', post=post)
        else:
            return self.redirect('/blog?error=You may delete only your own post')

    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
              return self.redirect('blog')
            if not self.user:
                return self.redirect('/signup')
            if post.user_id != self.user.key().id():
                return self.redirect('/blog')

            post.delete()
            self.redirect('/blog')
        else:
            return self.redirect('/login')


##"EditPost" handler.  Ensures (a)that post editor is logged in; (b)that the post editor owns the post.  Renders editpost.html page.  Ensures that editpost.html page contains subject and content information.  Updates post subject and content on permalink page and '/blog' page.
class EditPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
          return self.redirect('blog')
        if not self.user:
            self.redirect('/login')
        elif post.user_id == self.user.key().id():

            self.render('editpost.html', post=post)
        else:
            return self.redirect('/blog?error=You may edit only your own post')

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
          return self.redirect('blog')
        if not self.user:
            return self.redirect('/signup')
        subject = self.request.get('subject')
        content = self.request.get('content')
        if post.user_id != self.user.key().id():
            return self.redirect('/blog')
        if subject and content:
            post.subject = subject
            post.content = content
            post.put()

            self.redirect('/blog')
        else:
            error = "Subject and Content, Please."
            self.render('newpost.html', subject=subject, content=content,
                        error=error)


##"Signup" handler.  Renders signup-form.html.  Ensures submitted username, password, and optional email are valid, and that passwords match.  Stores parameters.
class Signup(BlogHandler):
    def get(self):
        self.render('signup-form.html')

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

    def done(self, *a, **kw):
        raise NotImplementedError


##"Register" handler. Registers new user; makes sure user does not already exist; renders welcome.html #page.
class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            return self.redirect("/blog?error=That user already exists")
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')


##"Login" handler.  Renders login-form.html; checks username and password for validity; logs user in and returns to updated '/blog' page.
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
            msg = "Invalid login"
            self.render('login-form.html', error = msg)


##"Logout" handler.  Logs logged-in user out and returns to '/blog' page.
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


##"Welcome" handler.  Renders welcome.html page, wecloming newly signed-up user.
class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')


##Routers##
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/likepost/([0-9]+)', LikePost),
                               ('/blog/unlikepost/([0-9]+)', UnlikePost),
                               ('/blog/newcomment/([0-9]+)', NewComment),
                               ('/blog/editcomment/([0-9]+)', EditComment),
                               ('/blog/deletecomment/([0-9]+)', DeleteComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/welcome', Welcome),
                               ],
                              debug=True)
