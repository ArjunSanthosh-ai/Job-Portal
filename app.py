from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///job_portal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # job_seeker, employer, admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    jobs = db.relationship('Job', backref='employer', lazy=True, foreign_keys='Job.employer_id')
    applications = db.relationship('Application', backref='applicant', lazy=True)

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    salary = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    company = db.Column(db.String(200), nullable=False)
    employer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    applications = db.relationship('Application', backref='job', lazy=True, cascade='all, delete-orphan')

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), default='pending')
    applied_at = db.Column(db.DateTime, default=datetime.utcnow)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Login successful!', 'success')
            
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'employer':
                return redirect(url_for('employer_dashboard'))
            else:
                return redirect(url_for('job_seeker_dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/job-seeker/dashboard')
def job_seeker_dashboard():
    if 'user_id' not in session or session['role'] != 'job_seeker':
        flash('Please login as a job seeker', 'error')
        return redirect(url_for('login'))
    
    jobs = Job.query.order_by(Job.created_at.desc()).all()
    applications = Application.query.filter_by(user_id=session['user_id']).all()
    applied_job_ids = [app.job_id for app in applications]
    
    return render_template('job_seeker_dashboard.html', jobs=jobs, applied_job_ids=applied_job_ids)

@app.route('/search-jobs')
def search_jobs():
    location = request.args.get('location', '')
    category = request.args.get('category', '')
    company = request.args.get('company', '')
    
    query = Job.query
    
    if location:
        query = query.filter(Job.location.ilike(f'%{location}%'))
    if category:
        query = query.filter(Job.category.ilike(f'%{category}%'))
    if company:
        query = query.filter(Job.company.ilike(f'%{company}%'))
    
    jobs = query.order_by(Job.created_at.desc()).all()
    
    if 'user_id' in session and session['role'] == 'job_seeker':
        applications = Application.query.filter_by(user_id=session['user_id']).all()
        applied_job_ids = [app.job_id for app in applications]
        return render_template('job_seeker_dashboard.html', jobs=jobs, applied_job_ids=applied_job_ids, 
                             search_location=location, search_category=category, search_company=company)
    
    return render_template('search_results.html', jobs=jobs)

@app.route('/apply/<int:job_id>', methods=['POST'])
def apply_job(job_id):
    if 'user_id' not in session or session['role'] != 'job_seeker':
        return jsonify({'success': False, 'message': 'Please login as a job seeker'})
    
    existing_application = Application.query.filter_by(job_id=job_id, user_id=session['user_id']).first()
    
    if existing_application:
        return jsonify({'success': False, 'message': 'You have already applied for this job'})
    
    new_application = Application(job_id=job_id, user_id=session['user_id'])
    db.session.add(new_application)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Application submitted successfully'})

@app.route('/employer/dashboard')
def employer_dashboard():
    if 'user_id' not in session or session['role'] != 'employer':
        flash('Please login as an employer', 'error')
        return redirect(url_for('login'))
    
    jobs = Job.query.filter_by(employer_id=session['user_id']).order_by(Job.created_at.desc()).all()
    return render_template('employer_dashboard.html', jobs=jobs)

@app.route('/employer/post-job', methods=['GET', 'POST'])
def post_job():
    if 'user_id' not in session or session['role'] != 'employer':
        flash('Please login as an employer', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        salary = request.form['salary']
        location = request.form['location']
        category = request.form['category']
        company = request.form['company']
        
        new_job = Job(
            title=title,
            description=description,
            salary=salary,
            location=location,
            category=category,
            company=company,
            employer_id=session['user_id']
        )
        
        db.session.add(new_job)
        db.session.commit()
        
        flash('Job posted successfully!', 'success')
        return redirect(url_for('employer_dashboard'))
    
    return render_template('post_job.html')

@app.route('/employer/edit-job/<int:job_id>', methods=['GET', 'POST'])
def edit_job(job_id):
    if 'user_id' not in session or session['role'] != 'employer':
        flash('Please login as an employer', 'error')
        return redirect(url_for('login'))
    
    job = Job.query.get_or_404(job_id)
    
    if job.employer_id != session['user_id']:
        flash('Unauthorized access', 'error')
        return redirect(url_for('employer_dashboard'))
    
    if request.method == 'POST':
        job.title = request.form['title']
        job.description = request.form['description']
        job.salary = request.form['salary']
        job.location = request.form['location']
        job.category = request.form['category']
        job.company = request.form['company']
        
        db.session.commit()
        flash('Job updated successfully!', 'success')
        return redirect(url_for('employer_dashboard'))
    
    return render_template('edit_job.html', job=job)

@app.route('/employer/delete-job/<int:job_id>', methods=['POST'])
def delete_job(job_id):
    if 'user_id' not in session or session['role'] != 'employer':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    job = Job.query.get_or_404(job_id)
    
    if job.employer_id != session['user_id']:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    db.session.delete(job)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Job deleted successfully'})

@app.route('/employer/view-applications/<int:job_id>')
def view_applications(job_id):
    if 'user_id' not in session or session['role'] != 'employer':
        flash('Please login as an employer', 'error')
        return redirect(url_for('login'))
    
    job = Job.query.get_or_404(job_id)
    
    if job.employer_id != session['user_id']:
        flash('Unauthorized access', 'error')
        return redirect(url_for('employer_dashboard'))
    
    applications = Application.query.filter_by(job_id=job_id).all()
    
    return render_template('view_applications.html', job=job, applications=applications)

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Please login as an admin', 'error')
        return redirect(url_for('login'))
    
    users = User.query.all()
    jobs = Job.query.all()
    applications = Application.query.all()
    
    stats = {
        'total_users': len(users),
        'job_seekers': len([u for u in users if u.role == 'job_seeker']),
        'employers': len([u for u in users if u.role == 'employer']),
        'total_jobs': len(jobs),
        'total_applications': len(applications)
    }
    
    return render_template('admin_dashboard.html', users=users, jobs=jobs, stats=stats)

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    user = User.query.get_or_404(user_id)
    
    if user.id == session['user_id']:
        return jsonify({'success': False, 'message': 'Cannot delete your own account'})
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'User deleted successfully'})

@app.route('/admin/delete-job/<int:job_id>', methods=['POST'])
def admin_delete_job(job_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    job = Job.query.get_or_404(job_id)
    db.session.delete(job)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Job deleted successfully'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
