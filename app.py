from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from marshmallow import Schema, fields, ValidationError
import os
from datetime import timedelta

db = SQLAlchemy()

class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///internflare.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv("JWT_SECRET", "change-this-secret")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=2)

# Schemas
class SignupSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True, load_only=True)
    name = fields.Str(required=False)

class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True, load_only=True)

class FeedbackSchema(Schema):
    message = fields.Str(required=True)
    rating = fields.Int(required=False)

class ProgressUpdateSchema(Schema):
    progress = fields.Int(required=True)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255))
    role = db.Column(db.String(50), default="intern")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    message = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class InternProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    progress = db.Column(db.Integer, default=0)
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    jwt = JWTManager(app)
    
    @app.before_request
    def enforce_json_content_type():
        # Only enforce for endpoints that expect a JSON body
        if request.method in ("POST", "PUT", "PATCH"):
            if not request.is_json:
                return jsonify({"errors": "Content-Type must be 'application/json'"}), 415

    @app.route("/", methods=["GET"]) 
    def index():
        return jsonify({"service": "InternFlare API", "status": "ok", "version": "1.0"}), 200

    @app.route("/favicon.ico")
    def favicon():
        return "", 204



    @app.route("/api/v1/auth/signup", methods=["POST"])
    def signup():
        try:
            data = SignupSchema().load(request.json)
        except ValidationError as err:
            return {"errors": err.messages}, 400
        if User.query.filter_by(email=data["email"]).first():
            return {"msg": "Email already registered"}, 400
        user = User(email=data["email"], name=data.get("name"))
        user.set_password(data["password"])
        db.session.add(user)
        db.session.commit()
        return {"id": user.id, "email": user.email, "name": user.name}, 201

    @app.route("/api/v1/auth/login", methods=["POST"])
    def login():
        try:
            data = LoginSchema().load(request.json)
        except ValidationError as err:
            return {"errors": err.messages}, 400
        user = User.query.filter_by(email=data["email"]).first()
        if not user or not user.check_password(data["password"]):
            return {"msg": "Bad credentials"}, 401
        access_token = create_access_token(identity=user.id)
        return {"access_token": access_token, "user": {"id": user.id, "email": user.email, "name": user.name}}

    @app.route("/api/v1/feedback", methods=["POST"])
    @jwt_required()
    def submit_feedback():
        try:
            data = FeedbackSchema().load(request.json)
        except ValidationError as err:
            return {"errors": err.messages}, 400
        user_id = get_jwt_identity()
        feedback = Feedback(user_id=user_id, message=data["message"], rating=data.get("rating"))
        db.session.add(feedback)
        db.session.commit()
        return {"id": feedback.id, "message": "Feedback submitted"}, 201

    @app.route("/api/v1/interns", methods=["GET"])
    @jwt_required()
    def list_interns():
        # Basic list with optional query param ?min_progress=50
        min_prog = request.args.get("min_progress", type=int)
        q = db.session.query(User, InternProgress).outerjoin(InternProgress, User.id == InternProgress.user_id)
        if min_prog is not None:
            q = q.filter(InternProgress.progress >= min_prog)
        results = []
        for user, prog in q.all():
            results.append({
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "progress": prog.progress if prog else 0
            })
        return jsonify(results)

    @app.route("/api/v1/interns/<int:user_id>/progress", methods=["PUT"])
    @jwt_required()
    def update_progress(user_id):
        try:
            data = ProgressUpdateSchema().load(request.json)
        except ValidationError as err:
            return {"errors": err.messages}, 400
        prog = InternProgress.query.filter_by(user_id=user_id).first()
        if not prog:
            prog = InternProgress(user_id=user_id, progress=data["progress"])
            db.session.add(prog)
        else:
            prog.progress = data["progress"]
        db.session.commit()
        return {"user_id": user_id, "progress": prog.progress}

    return app

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)