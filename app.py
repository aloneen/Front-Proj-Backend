from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///postit.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'  # Замените на надёжный ключ
db = SQLAlchemy(app)
CORS(app,
     resources={r"*": {"origins": "*", "methods": ["GET","POST","PUT","DELETE","OPTIONS"]}},
     supports_credentials=True
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='User')
    posts = db.relationship('Post', backref='author', lazy=True, cascade="all, delete-orphan")
    comments = db.relationship('Comment', backref='author', lazy=True, cascade="all, delete-orphan")


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True, cascade="all, delete-orphan")


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id', ondelete='CASCADE'), nullable=False)


def jwt_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Пропускаем preflight OPTIONS‑запрос
        if request.method == 'OPTIONS':
            return jsonify({}), 200
        auth_header = request.headers.get('Authorization', None)
        if auth_header is None or not auth_header.startswith("Bearer "):
            return jsonify({'error': 'Token is missing'}), 401
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        request.user_id = payload['user_id']
        return func(*args, **kwargs)
    return wrapper



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


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'Email и password обязательны'}), 400

    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
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
        'username': post.author.username
    } for post in posts]
    return jsonify(result), 200


@app.route('/posts', methods=['POST'])
@jwt_required
def create_post():
    data = request.get_json() or {}
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()
    if not title or not content:
        return jsonify({'error': 'Title и content обязательны'}), 400

    user = User.query.get(request.user_id)
    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404

    new_post = Post(title=title, content=content, user_id=user.id)
    db.session.add(new_post)
    db.session.commit()
    return jsonify({
        'message': 'Пост успешно создан',
        'post': {
            'id': new_post.id,
            'title': new_post.title,
            'content': new_post.content,
            'created_at': new_post.created_at.isoformat(),
            'user_id': new_post.user_id,
            'username': user.username
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
        'user_username': comment.author.username
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
    return jsonify({
        'message': 'Комментарий успешно создан',
        'comment': {
            'id': new_comment.id,
            'content': new_comment.content,
            'created_at': new_comment.created_at.isoformat(),
            'user_id': new_comment.user_id,
            'user_username': user.username
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
        'role': user.role
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
    if request.method == 'OPTIONS':
        return {}, 200  # preflight

    data = request.get_json() or {}
    new_title = data.get('title', '').strip()
    new_content = data.get('content', '').strip()

    if not new_title or not new_content:
        return jsonify({'error': 'Title и Content обязательны'}), 400

    post = Post.query.get(post_id)
    if not post:
        return jsonify({'error': 'Пост не найден'}), 404

    user = User.query.get(request.user_id)

    if not user or (user.role != 'Admin' and post.user_id != user.id):
        return jsonify({'error': 'Доступ запрещён'}), 403

    post.title = new_title
    post.content = new_content
    db.session.commit()

    return jsonify({
        'message': 'Пост успешно обновлён',
        'post': {
            'id': post.id,
            'title': post.title,
            'content': post.content,
            'created_at': post.created_at.isoformat(),
            'user_id': post.user_id,
            'username': post.author.username
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



if __name__ == '__main__':
    # Для первого запуска, если необходимо создать базу данных, раскомментируйте:
    # with app.app_context():
    #     db.drop_all()
    #     db.create_all()
    app.run(debug=True)
