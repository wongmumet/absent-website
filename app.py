# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode
from io import BytesIO
import pandas as pd
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attendance.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Model untuk User
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    organization = db.Column(db.String(100))  # IPNU/IPPNU
    is_admin = db.Column(db.Boolean, default=False)
    attendances = db.relationship('Attendance', backref='user', lazy=True)

# Model untuk Attendance
class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    qr_code = db.Column(db.String(100), nullable=False)

# Model untuk QR Codes
class QRCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(100), unique=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

# Update route login untuk mengarahkan ke halaman spesifik
@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email, is_admin=False).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('user_dashboard'))
            
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        organization = request.form.get('organization')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('signup'))
            
        hashed_password = generate_password_hash(password)
        new_user = User(email=email, password=hashed_password, 
                       name=name, organization=organization)
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
    return render_template('signup.html')

# Routes untuk user
@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    return render_template('user_dashboard.html')

@app.route('/user/scan', methods=['POST'])
@login_required
def scan_qr():
    qr_code = request.form.get('qr_code')
    qr = QRCode.query.filter_by(code=qr_code, is_active=True).first()
    
    if not qr:
        return jsonify({'success': False, 'message': 'Invalid QR Code'})
        
    attendance = Attendance(user_id=current_user.id, qr_code=qr_code)
    db.session.add(attendance)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Attendance recorded successfully'})

# Routes untuk admin
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # List email admin yang diizinkan
        allowed_admin_emails = ['admin1@example.com', 'admin2@example.com']
        
        if email not in allowed_admin_emails:
            flash('Unauthorized email address')
            return redirect(url_for('admin_login'))
            
        user = User.query.filter_by(email=email, is_admin=True).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin_dashboard'))
            
        flash('Invalid email or password')
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    attendances = Attendance.query.order_by(Attendance.timestamp.desc()).all()
    return render_template('admin_dashboard.html', attendances=attendances)

@app.route('/admin/generate-qr')
@login_required
def generate_qr():
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
        
    # Generate unique code
    import uuid
    code = str(uuid.uuid4())
    
    # Create QR code image
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(code)
    qr.make(fit=True)
    qr_image = qr.make_image(fill_color="black", back_color="white")
    
    # Save code to database
    new_qr = QRCode(code=code)
    db.session.add(new_qr)
    db.session.commit()
    
    # Save QR image to BytesIO object
    img_io = BytesIO()
    qr_image.save(img_io, 'PNG')
    img_io.seek(0)
    
    return send_file(img_io, mimetype='image/png', as_attachment=True, 
                    download_name=f'qr_code_{code[:8]}.png')

@app.route('/admin/export-excel')
@login_required
def export_excel():
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
        
    # Get all attendance records
    attendances = Attendance.query.join(User).all()
    
    # Create DataFrame
    data = []
    for attendance in attendances:
        data.append({
            'Name': attendance.user.name,
            'Email': attendance.user.email,
            'Organization': attendance.user.organization,
            'Time': attendance.timestamp,
            'QR Code': attendance.qr_code
        })
    
    df = pd.DataFrame(data)
    
    # Save to Excel
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False)
    output.seek(0)
    
    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                    as_attachment=True, download_name='attendance_report.xlsx')

def create_default_admins():
    # Daftar admin default dengan email dan password mereka
    default_admins = [
        {
            'email': 'admin1@example.com',
            'password': 'admin123',  # Ganti dengan password yang lebih aman
            'name': 'Admin Satu',
            'organization': 'IPNU',
            'is_admin': True
        },
        {
            'email': 'admin2@example.com',
            'password': 'admin456',  # Ganti dengan password yang lebih aman
            'name': 'Admin Dua',
            'organization': 'IPPNU',
            'is_admin': True
        }
    ]

    for admin_data in default_admins:
        # Cek apakah admin sudah ada
        existing_admin = User.query.filter_by(email=admin_data['email']).first()
        if not existing_admin:
            # Buat admin baru jika belum ada
            new_admin = User(
                email=admin_data['email'],
                password=generate_password_hash(admin_data['password']),
                name=admin_data['name'],
                organization=admin_data['organization'],
                is_admin=True
            )
            db.session.add(new_admin)
    
    db.session.commit()

# Modifikasi bagian if __name__ == '__main__':
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_admins()  # Panggil fungsi untuk membuat admin default
    app.run(debug=True)