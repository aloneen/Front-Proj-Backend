from flask import Flask, request, jsonify
from flask_jwt_extended import get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

from flask import Flask, request, jsonify, url_for, send_from_directory, abort
from werkzeug.utils import secure_filename


import jwt
from functools import wraps

import os
import uuid



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///postit.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'  # Замените на надёжный ключ
db = SQLAlchemy(app)
CORS(app,
     resources={r"*": {"origins": "*", "methods": ["GET","POST","PUT","DELETE","OPTIONS"]}},
     supports_credentials=True
)



BASE_UPLOAD = os.path.join(app.root_path, 'static', 'uploads')
POSTS_UPLOAD = os.path.join(BASE_UPLOAD, 'posts')
AVATARS_UPLOAD = os.path.join(BASE_UPLOAD, 'avatars')
ALLOWED_EXT = {'png','jpg','jpeg','gif'}


for d in (POSTS_UPLOAD, AVATARS_UPLOAD):
    os.makedirs(d, exist_ok=True)

def allowed_file(fn):
    return '.' in fn and fn.rsplit('.',1)[1].lower() in ALLOWED_EXT


# Likes table (many-to-many)
likes = db.Table('likes',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('post_id', db.Integer, db.ForeignKey('post.id'), primary_key=True)
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='User')
    posts = db.relationship('Post', backref='author', lazy=True, cascade="all, delete-orphan")
    comments = db.relationship('Comment', backref='author', lazy=True, cascade="all, delete-orphan")
    avatar = db.Column(db.String(256), nullable=True)
    is_active = db.Column(db.Boolean, default=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')
    likers = db.relationship('User', secondary=likes, backref='liked_posts')

    images = db.relationship(
        'PostImage',
        backref = db.backref('post', lazy=True),
        cascade = 'all, delete-orphan',
        passive_deletes = True
    )

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id', ondelete='CASCADE'), nullable=False)


class PostImage(db.Model):
    id      = db.Column(db.Integer, primary_key=True)
    filename= db.Column(db.String(256), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id', ondelete='CASCADE'), nullable=False)


# Category model
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    posts = db.relationship('Post', backref='category', lazy=True)


#
# def jwt_required(func):
#     @wraps(func)
#     def wrapper(*args, **kwargs):
#         # Пропускаем preflight OPTIONS‑запрос
#         if request.method == 'OPTIONS':
#             return jsonify({}), 200
#         auth_header = request.headers.get('Authorization', None)
#         if auth_header is None or not auth_header.startswith("Bearer "):
#             return jsonify({'error': 'Token is missing'}), 401
#         token = auth_header.split(" ")[1]
#         try:
#             payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
#         except jwt.ExpiredSignatureError:
#             return jsonify({'error': 'Token expired'}), 401
#         except jwt.InvalidTokenError:
#             return jsonify({'error': 'Invalid token'}), 401
#         request.user_id = payload['user_id']
#         return func(*args, **kwargs)
#
#         request.user_id = payload['user_id']
#         user = User.query.get(request.user_id)
#         if not user or not user.is_active:
#             return jsonify({'error': 'Account inactive'}), 403
#         return func(*args, **kwargs)
#     return wrapper

def jwt_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # allow CORS preflight
        if request.method == 'OPTIONS':
            return jsonify({}), 200

        auth_header = request.headers.get('Authorization', None)
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token is missing'}), 401

        token = auth_header.split(' ')[1]
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

        # load the user
        user = User.query.get(payload['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404
        if not user.is_active:
            return jsonify({'error': 'Account is banned'}), 403

        # stash the id for downstream handlers
        request.user_id = user.id
        return func(*args, **kwargs)
    return wrapper



def avatar_url_for(user):
    if not user.avatar:
        return None
    return url_for('uploaded_file', folder='avatars', filename=user.avatar, _external=True)




@app.route('/uploads/<folder>/<filename>')
def uploaded_file(folder, filename):
    if folder == 'posts':
        directory = POSTS_UPLOAD
    elif folder == 'avatars':
        directory = AVATARS_UPLOAD
    else:
        return abort(404)
    return send_from_directory(directory, filename)



@app.route('/posts/<int:post_id>/images', methods=['POST','OPTIONS'])
@jwt_required
def upload_post_images(post_id):
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    post = Post.query.get_or_404(post_id)
    if not request.files.getlist('images'):
        return jsonify({'error': 'No images provided'}), 400

    urls = []
    for file in request.files.getlist('images'):
        if file and allowed_file(file.filename):
            fn = secure_filename(file.filename)
            unique = f"{uuid.uuid4().hex}_{fn}"
            path = os.path.join(POSTS_UPLOAD, unique)
            file.save(path)

            img = PostImage(filename=unique, post_id=post.id)
            db.session.add(img)
            urls.append(
            url_for('uploaded_file', folder='posts', filename=unique, _external=True)
            )

    db.session.commit()
    return jsonify({'images': urls}), 201






@app.route('/user/avatar', methods=['POST','OPTIONS'])
@jwt_required
def upload_avatar():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    file = request.files.get('avatar')
    if not file or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid or missing avatar file'}), 400

    fn = secure_filename(file.filename)
    unique = f"{uuid.uuid4().hex}_{fn}"
    path = os.path.join(AVATARS_UPLOAD, unique)
    file.save(path)

    user = User.query.get(request.user_id)
    user.avatar = unique
    db.session.commit()

    url = url_for('uploaded_file', folder='avatars', filename=unique, _external=True)
    return jsonify({'avatar_url': url}), 200


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')

    if not username or not email or not password:
        return jsonify({'error': 'Username, email и password обязательны'}), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'error': 'Пользователь с таким именем или email уже существует'}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({
        'message': 'Регистрация успешна',
        'user': {
            'id': new_user.id,
            'username': new_user.username,
            'email': new_user.email
        }
    }), 201


# @app.route('/login', methods=['POST'])
# def login():
#     data = request.get_json() or {}
#     email = data.get('email', '').strip()
#     password = data.get('password', '')
#
#     if not email or not password:
#         return jsonify({'error': 'Email и password обязательны'}), 400
#
#     user = User.query.filter_by(email=email).first()
#     if user and check_password_hash(user.password, password):
#         token = jwt.encode(
#             {'user_id': user.id, 'exp': datetime.utcnow() + timedelta(hours=1)},
#             app.config['SECRET_KEY'], algorithm='HS256'
#         )
#         return jsonify({
#             'message': 'Вход успешен',
#             'user': {
#                 'id': user.id,
#                 'username': user.username,
#                 'email': user.email,
#                 'role': user.role
#             },
#             'token': token
#         }), 200
#     else:
#         return jsonify({'error': 'Неверные учетные данные'}), 401


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'Email и password обязательны'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'Неверные учетные данные'}), 401

    # ---- new: ban check ----
    if not user.is_active:
        return jsonify({'error': 'Ваш аккаунт заблокирован'}), 403

    if check_password_hash(user.password, password):
        token = jwt.encode(
            {'user_id': user.id, 'exp': datetime.utcnow() + timedelta(hours=1)},
            app.config['SECRET_KEY'], algorithm='HS256'
        )
        return jsonify({
            'message': 'Вход успешен',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role
            },
            'token': token
        }), 200
    else:
        return jsonify({'error': 'Неверные учетные данные'}), 401


@app.route('/user', methods=['GET'])
@jwt_required
def get_current_user():
    user = User.query.get(request.user_id)
    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404
    return jsonify({
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role
        }
    }), 200



@app.route('/posts', methods=['GET'])
def get_posts():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    result = [{
        'id': post.id,
        'title': post.title,
        'content': post.content,
        'created_at': post.created_at.isoformat(),
        'user_id': post.user_id,
        'username': post.author.username,
        'category_id': post.category_id,  # ← add this
        'category_name': post.category.name if post.category else None,
        'images': [
            {
                'id':  img.id,
                'url': url_for(
                    'uploaded_file',
                    folder='posts',
                    filename=img.filename,
                    _external=True
                )
            }
            for img in post.images
        ],
        'author_avatar': avatar_url_for(post.author)
    } for post in posts]
    return jsonify(result), 200




@app.route('/posts/<int:post_id>', methods=['GET'])
def get_post_detail(post_id):
    p = Post.query.get_or_404(post_id)
    return jsonify({
        'id': p.id,
        'title': p.title,
        'content': p.content,
        'category_id': p.category_id,
        'category_name': p.category.name if p.category else None,
        'created_at': p.created_at.isoformat(),
        'user_id': p.user_id,
        'username': p.author.username,
        'images': [
            {
                'id':  img.id,
                'url': url_for(
                    'uploaded_file',
                    folder='posts',
                    filename=img.filename,
                    _external=True
                )
            }
            for img in p.images
        ],
        'author_avatar': avatar_url_for(p.author)
    }), 200


@app.route('/posts', methods=['POST', 'OPTIONS'])
@jwt_required
def create_post():
    # allow CORS preflight
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json() or {}
    title       = data.get('title', '').strip()
    content     = data.get('content', '').strip()
    category_id = data.get('category_id')

    # validate all fields
    if not title or not content or category_id is None:
        return jsonify({'error': 'Title, content и category_id обязательны'}), 400

    # find user
    user = User.query.get(request.user_id)
    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404

    # find category
    category = Category.query.get(category_id)
    if not category:
        return jsonify({'error': 'Категория не найдена'}), 404

    # create post
    new_post = Post(
        title=title,
        content=content,
        user_id=user.id,
        category_id=category.id
    )
    db.session.add(new_post)
    db.session.commit()

    return jsonify({
        'message': 'Пост успешно создан',
        'post': {
            'id':            new_post.id,
            'title':         new_post.title,
            'content':       new_post.content,
            'category_id':   category.id,
            'category_name': category.name,
            'created_at':    new_post.created_at.isoformat(),
            'user_id':       new_post.user_id,
            'username':      user.username
        }
    }), 201



@app.route('/posts/<int:post_id>/comments', methods=['GET'])
def get_comments(post_id):
    comments = Comment.query.filter_by(post_id=post_id).order_by(Comment.created_at).all()
    result = [{
        'id': comment.id,
        'content': comment.content,
        'created_at': comment.created_at.isoformat(),
        'user_id': comment.user_id,
        'user_username': comment.author.username,
        'user_avatar': avatar_url_for(comment.author)
    } for comment in comments]
    return jsonify(result), 200


@app.route('/posts/<int:post_id>/comments', methods=['POST'])
@jwt_required
def create_comment(post_id):
    data = request.get_json() or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': 'Content обязательный'}), 400

    user = User.query.get(request.user_id)
    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404

    post = Post.query.get(post_id)
    if not post:
        return jsonify({'error': 'Пост не найден'}), 404

    new_comment = Comment(content=content, user_id=user.id, post_id=post.id)
    db.session.add(new_comment)
    db.session.commit()

    # build avatar URL
    avatar_url = None
    if user.avatar:
        avatar_url = url_for('uploaded_file', folder='avatars', filename=user.avatar, _external=True)

    return jsonify({
        'message': 'Комментарий успешно создан',
        'comment': {
            'id': new_comment.id,
            'content': new_comment.content,
            'created_at': new_comment.created_at.isoformat(),
            'user_id': new_comment.user_id,
            'user_username': user.username,
            'user_avatar': avatar_url     # ← include this
        }
    }), 201



# Эндпоинты для администратора

@app.route('/users', methods=['GET'])
@jwt_required
def get_users():
    current_user = User.query.get(request.user_id)
    if not current_user or current_user.role != 'Admin':
        return jsonify(
            {'error': 'Доступ запрещён. Только администратор может просматривать список пользователей.'}), 403

    users = User.query.all()
    result = [{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'is_active': user.is_active
    } for user in users]
    return jsonify(result), 200


@app.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required
def admin_delete_user(user_id):
    current_user = User.query.get(request.user_id)
    if not current_user or current_user.role != 'Admin':
        return jsonify({'error': 'Доступ запрещён. Только администратор может удалять пользователей.'}), 403

    user_to_delete = User.query.get(user_id)
    if not user_to_delete:
        return jsonify({'error': 'Пользователь не найден'}), 404

    db.session.delete(user_to_delete)
    db.session.commit()
    return jsonify({'message': 'Пользователь удалён'}), 200


@app.route('/posts/<int:post_id>', methods=['DELETE', 'OPTIONS'])
@jwt_required
def delete_post(post_id):
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    post = Post.query.get(post_id)
    if not post:
        return jsonify({'error': 'Пост не найден'}), 404

    user = User.query.get(request.user_id)
    # Разрешаем удаление, если пользователь - админ или автор поста
    if not user or (user.role != 'Admin' and post.user_id != user.id):
        return jsonify({'error': 'Доступ запрещён'}), 403

    db.session.delete(post)
    db.session.commit()
    return jsonify({'message': 'Пост удалён'}), 200

@app.route('/comments/<int:comment_id>', methods=['DELETE', 'OPTIONS'])
@jwt_required
def delete_comment(comment_id):
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    comment = Comment.query.get(comment_id)
    if not comment:
        return jsonify({'error': 'Комментарий не найден'}), 404

    user = User.query.get(request.user_id)
    if not user:
        return jsonify({'error': 'Доступ запрещён'}), 403

    if user.role not in ['Admin', 'Moderator'] and comment.user_id != user.id:
        return jsonify({'error': 'Доступ запрещён'}), 403

    db.session.delete(comment)
    db.session.commit()
    return jsonify({'message': 'Комментарий удалён'}), 200


@app.route('/posts/<int:post_id>', methods=['PUT', 'OPTIONS'])
@jwt_required
def update_post(post_id):
    # allow CORS preflight
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json() or {}
    new_title      = data.get('title', '').strip()
    new_content    = data.get('content', '').strip()
    new_category_id = data.get('category_id')

    # validate all fields
    if not new_title or not new_content or new_category_id is None:
        return jsonify({'error': 'Title, content и category_id обязательны'}), 400

    # load post
    post = Post.query.get(post_id)
    if not post:
        return jsonify({'error': 'Пост не найден'}), 404

    # permission check
    user = User.query.get(request.user_id)
    if not user or (user.role != 'Admin' and post.user_id != user.id):
        return jsonify({'error': 'Доступ запрещён'}), 403

    # find new category
    category = Category.query.get(new_category_id)
    if not category:
        return jsonify({'error': 'Категория не найдена'}), 404

    # apply updates
    post.title       = new_title
    post.content     = new_content
    post.category_id = category.id
    db.session.commit()

    return jsonify({
        'message': 'Пост успешно обновлён',
        'post': {
            'id':            post.id,
            'title':         post.title,
            'content':       post.content,
            'category_id':   category.id,
            'category_name': category.name,
            'created_at':    post.created_at.isoformat(),
            'updated_at':    post.updated_at.isoformat() if hasattr(post, 'updated_at') else None,
            'user_id':       post.user_id,
            'username':      post.author.username
        }
    }), 200

@app.route('/comments', methods=['GET'])
@jwt_required
def get_all_comments():
    user = User.query.get(request.user_id)
    if not user or user.role not in ['Admin', 'Moderator']:
        return jsonify({'error': 'Доступ запрещён. Только администратор или модератор могут просматривать комментарии.'}), 403

    comments = Comment.query.order_by(Comment.created_at.desc()).all()
    result = [{
        'id': comment.id,
        'content': comment.content,
        'created_at': comment.created_at.isoformat(),
        'user_id': comment.user_id,
        'user_username': comment.author.username,
        'post_id': comment.post_id
    } for comment in comments]
    return jsonify(result), 200



@app.route('/categories', methods=['GET'])
def get_categories():
    return jsonify([{'id': c.id, 'name': c.name} for c in Category.query.all()])


# in app.py

@app.route('/categories', methods=['GET', 'POST', 'OPTIONS'])
@jwt_required  # you can make this optional for GET if you like
def handle_categories():
    # CORS preflight
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    # GET: list all categories
    if request.method == 'GET':
        cats = Category.query.all()
        return jsonify([{'id': c.id, 'name': c.name} for c in cats]), 200

    # POST: create a new category
    # permission: only Admin or Moderator
    user = User.query.get(request.user_id)
    if user.role not in ['Admin', 'Moderator']:
        return jsonify({'error': 'Forbidden'}), 403

    data = request.get_json() or {}
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Name is required'}), 400
    if Category.query.filter_by(name=name).first():
        return jsonify({'error': 'Category already exists'}), 400

    cat = Category(name=name)
    db.session.add(cat)
    db.session.commit()
    return jsonify({'id': cat.id, 'name': cat.name}), 201








@app.route('/posts/<int:post_id>/like', methods=['POST'])
@jwt_required                    # ← ensure this is here
def like_post(post_id):
    user_id = request.user_id    # now safe to call
    post = Post.query.get_or_404(post_id)
    user = User.query.get(user_id)
    if user in post.likers:
        return jsonify({'message': 'Already liked'}), 400
    post.likers.append(user)
    db.session.commit()
    return jsonify({'message': 'Liked'}), 200

# Unlike a post
@app.route('/posts/<int:post_id>/unlike', methods=['DELETE'])
@jwt_required                   # ← and also here
def unlike_post(post_id):
    user_id = request.user_id
    post = Post.query.get_or_404(post_id)
    user = User.query.get(user_id)
    if user not in post.likers:
        return jsonify({'message': 'Not liked yet'}), 400
    post.likers.remove(user)
    db.session.commit()
    return jsonify({'message': 'Unliked'}), 200

# Get post likes count
@app.route('/posts/<int:post_id>/likes', methods=['GET'])
def get_post_likes(post_id):
    post = Post.query.get_or_404(post_id)
    # total count
    count = len(post.likers)
    # default to not liked
    liked = False

    # check for an Authorization header
    auth_header = request.headers.get('Authorization', None)
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        try:
            # decode with your same SECRET_KEY
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(payload['user_id'])
            if user and user in post.likers:
                liked = True
        except jwt.PyJWTError:
            # expired/invalid token → treat as not‑logged‑in
            pass

    # return both count and liked to match your Redux slice
    return jsonify({
        'likes': count,
        'liked': liked
    }), 200

@app.route('/user/profile', methods=['GET','PUT','OPTIONS'])
@jwt_required
def user_profile():
    # allow CORS preflight
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    # ---- GET: return profile + posts ----
    if request.method == 'GET':
        u = User.query.get_or_404(request.user_id)
        avatar_url = None
        if u.avatar:
            avatar_url = url_for('uploaded_file',
                                 folder='avatars',
                                 filename=u.avatar,
                                 _external=True)
        user_posts = [{
            'id': p.id,
            'title': p.title,
            'images': [
                url_for('uploaded_file', folder='posts', filename=img.filename, _external=True)
                for img in p.images
            ]
        } for p in u.posts]
        return jsonify({
            'user': {
                'id':         u.id,
                'username':   u.username,
                'email':      u.email,
                'role':       u.role,
                'avatar_url': avatar_url
            },
            'posts': user_posts
        }), 200

    # ---- PUT: update username/email ----
    data = request.get_json() or {}
    new_username = data.get('username', '').strip()
    new_email    = data.get('email', '').strip()
    if not new_username or not new_email:
        return jsonify({'error': 'Username and email are required'}), 400

    # ensure uniqueness
    if User.query.filter(User.id != request.user_id, User.username == new_username).first():
        return jsonify({'error': 'Username already taken'}), 400
    if User.query.filter(User.id != request.user_id, User.email == new_email).first():
        return jsonify({'error': 'Email already taken'}), 400

    user = User.query.get_or_404(request.user_id)
    user.username = new_username
    user.email    = new_email
    db.session.commit()

    avatar_url = None
    if user.avatar:
        avatar_url = url_for('uploaded_file',
                             folder='avatars',
                             filename=user.avatar,
                             _external=True)

    return jsonify({
        'user': {
            'id':         user.id,
            'username':   user.username,
            'email':      user.email,
            'role':       user.role,
            'avatar_url': avatar_url
        }
    }), 200




@app.route('/posts/<int:post_id>/images/<int:image_id>', methods=['DELETE','OPTIONS'])
@jwt_required
def delete_post_image(post_id, image_id):
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    img = PostImage.query.get_or_404(image_id)
    if img.post_id != post_id:
        return jsonify({'error': 'Image doesn’t belong to that post'}), 400

    # permission: only the post’s author or admin
    user = User.query.get(request.user_id)
    post = Post.query.get(post_id)
    if user.role != 'Admin' and post.user_id != user.id:
        return jsonify({'error': 'Forbidden'}), 403

    # delete file from disk
    try:
        os.remove(os.path.join(POSTS_UPLOAD, img.filename))
    except OSError:
        pass

    db.session.delete(img)
    db.session.commit()
    return jsonify({'message': 'Image deleted'}), 200



# Delete a category (Moderator or Admin)
@app.route('/categories/<int:cat_id>', methods=['DELETE','OPTIONS'])
@jwt_required
def delete_category(cat_id):
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    user = User.query.get(request.user_id)
    if user.role not in ['Admin', 'Moderator']:
        return jsonify({'error': 'Forbidden'}), 403

    cat = Category.query.get_or_404(cat_id)
    db.session.delete(cat)
    db.session.commit()
    return jsonify({'message': 'Category deleted'}), 200


# Change a user’s role (Admin only)
@app.route('/users/<int:user_id>/role', methods=['PUT','OPTIONS'])
@jwt_required
def change_user_role(user_id):
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    current = User.query.get(request.user_id)
    if not current or current.role != 'Admin':
        return jsonify({'error': 'Forbidden'}), 403

    data = request.get_json() or {}
    new_role = data.get('role', '').strip()
    if new_role not in ['User', 'Moderator', 'Admin']:
        return jsonify({'error': 'Invalid role'}), 400

    user = User.query.get_or_404(user_id)
    user.role = new_role
    db.session.commit()
    return jsonify({'id': user.id, 'role': user.role}), 200



@app.route('/users/<int:user_id>/active', methods=['PUT','OPTIONS'])
@jwt_required
def set_user_active(user_id):
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    current = User.query.get(request.user_id)
    if current.role != 'Admin':
        return jsonify({'error': 'Forbidden'}), 403

    data = request.get_json() or {}
    is_active = data.get('is_active')
    if not isinstance(is_active, bool):
        return jsonify({'error': 'is_active must be true or false'}), 400

    user = User.query.get_or_404(user_id)
    user.is_active = is_active
    db.session.commit()
    return jsonify({'id': user.id, 'is_active': user.is_active}), 200




if __name__ == '__main__':
    # Для первого запуска, если необходимо создать базу данных, раскомментируйте:

    # with app.app_context():
    #     db.drop_all()
    #     db.create_all()

    app.run(debug=True)
