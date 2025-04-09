
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
from flask_bcrypt import Bcrypt



app = Flask(__name__)
CORS(app)

# Конфигурация
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///postit.db'
app.config['SECRET_KEY'] = 'secret-key'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

db = SQLAlchemy(app)
jwt = JWTManager(app)

bcrypt = Bcrypt(app)

# ---------- Модели ----------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(20))  # Admin, Moderator, User

    posts = db.relationship('Post', backref='user', lazy=True)
    comments = db.relationship('Comment', backref='user', lazy=True)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150))
    content = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    comments = db.relationship('Comment', backref='post', lazy=True)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# ---------- Вспомогательные функции ----------

def is_admin():
    current_user = get_jwt_identity()
    user = User.query.filter_by(id=current_user).first()
    return user.role == 'Admin'


# ---------- Аутентификация ----------

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'message': 'Missing username, email, or password'}), 400

    # check if user exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'message': 'User already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201



@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity={'id': user.id, 'role': user.role})
        return jsonify({'access_token': access_token}), 200

    return jsonify({'message': 'Invalid credentials'}), 401


# ---------- CRUD Users ----------

@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    users = User.query.all()
    return jsonify([{'id': u.id, 'username': u.username, 'email': u.email, 'role': u.role} for u in users])


@app.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    if not is_admin():
        return jsonify({'message': 'Access denied'}), 403
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted'})


# ---------- CRUD Posts ----------
# ---------- CRUD Posts ----------

@app.route('/posts', methods=['GET'])
def get_posts():
    # current_user = get_jwt_identity()
    # posts = Post.query.filter_by(user_id=current_user).all()

    posts = Post.query.all()

    return jsonify([
        {
            'id': p.id,
            'title': p.title,
            'content': p.content,
            'user_id': p.user_id,
            'comments': [{'id': c.id, 'content': c.content, 'user_id': c.user_id} for c in p.comments]
        } for p in posts
    ])

@app.route('/posts', methods=['POST'])
@jwt_required()
def create_post():
    data = request.get_json()
    user_id = get_jwt_identity()
    post = Post(title=data['title'], content=data['content'], user_id=user_id)
    db.session.add(post)
    db.session.commit()
    return jsonify({'message': 'Post created'}), 201

@app.route('/posts/<int:post_id>', methods=['PUT'])
@jwt_required()
def update_post(post_id):
    data = request.get_json()
    post = Post.query.get_or_404(post_id)
    user_id = get_jwt_identity()
    if post.user_id != user_id and not is_admin():
        return jsonify({'message': 'Unauthorized'}), 403
    post.title = data['title']
    post.content = data['content']
    db.session.commit()
    return jsonify({'message': 'Post updated'})

@app.route('/posts/<int:post_id>', methods=['DELETE'])
@jwt_required()
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    user_id = get_jwt_identity()
    if post.user_id != user_id and not is_admin():
        return jsonify({'message': 'Unauthorized'}), 403
    db.session.delete(post)
    db.session.commit()
    return jsonify({'message': 'Post deleted'})

# ---------- CRUD Comments ----------

@app.route('/comments', methods=['POST'])
@jwt_required()
def create_comment():
    data = request.get_json()
    user_id = get_jwt_identity()
    comment = Comment(content=data['content'], post_id=data['post_id'], user_id=user_id)
    db.session.add(comment)
    db.session.commit()
    return jsonify({'message': 'Comment created'}), 201

@app.route('/comments/<int:comment_id>', methods=['PUT'])
@jwt_required()
def update_comment(comment_id):
    data = request.get_json()
    comment = Comment.query.get_or_404(comment_id)
    user_id = get_jwt_identity()
    if comment.user_id != user_id and not is_admin():
        return jsonify({'message': 'Unauthorized'}), 403
    comment.content = data['content']
    db.session.commit()
    return jsonify({'message': 'Comment updated'})

@app.route('/comments/<int:comment_id>', methods=['DELETE'])
@jwt_required()
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    user_id = get_jwt_identity()
    if comment.user_id != user_id and not is_admin():
        return jsonify({'message': 'Unauthorized'}), 403
    db.session.delete(comment)
    db.session.commit()
    return jsonify({'message': 'Comment deleted'})

@app.route('/commments/<int:post_id>', methods=['GET'])
def get_comment(post_id):
    comment = Comment.query.get_or_404(post_id)
    return jsonify({'message': 'Comment found'})


# ---------- Main ----------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
