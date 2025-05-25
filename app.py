from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, Employee, LeaveRequest, BackupAcknowledgement
from datetime import datetime, timedelta
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from sqlalchemy import extract
import re
from collections import defaultdict
import calendar
import secrets
import traceback
import sys
import logging
from tokens import generate_reset_token, verify_reset_token
from utils import send_reset_email
import os
from dotenv import load_dotenv
# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Database Configuration
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:akhilcheedalla@localhost/leave_management'

# Email configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

# Debug output to verify configuration loaded correctly
logger.info(f"Mail server: {app.config['MAIL_SERVER']}")
logger.info(f"Mail port: {app.config['MAIL_PORT']}")
logger.info(f"Mail username: {app.config['MAIL_USERNAME']}")
logger.info(f"Mail TLS enabled: {app.config['MAIL_USE_TLS']}")
logger.info(f"Mail SSL enabled: {app.config['MAIL_USE_SSL']}")

# Initialize extensions
db.init_app(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
mail = Mail(app)

# Helper function to calculate leave days excluding Sundays
def calculate_leave_days_excluding_sundays(start_date, end_date):
    days = 0
    current_date = start_date
    while current_date <= end_date:
        if current_date.weekday() != 6:  # 6 = Sunday
            days += 1
        current_date += timedelta(days=1)
    return days

def get_manager_for_employee(employee_id):
    try:
        logger.debug(f"Fetching employee with ID: {employee_id}")
        
        employee = Employee.query.get(employee_id)
        if employee:
            logger.debug(f"Employee found: {employee.name}, Manager ID: {employee.manager_id}")
        else:
            logger.warning(f"Employee with ID {employee_id} not found.")

        if employee and employee.manager_id:
            manager = Employee.query.filter_by(id=employee.manager_id, role='manager').first()
            if manager:
                logger.debug(f"Manager found: {manager.name}, Manager Email: {manager.email}")
                return manager
            else:
                logger.warning(f"Manager not found for employee ID: {employee_id}")
        else:
            logger.warning("Employee does not have a manager_id set.")

        return None
    except Exception as e:
        logger.error(f"Error in get_manager_for_employee: {e}")
        traceback.print_exc()
        return None

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        employee = Employee.query.filter_by(email=email).first()
        
        if employee and employee.check_password(password):
            session['user_id'] = employee.id
            session['role'] = employee.role
            session['username'] = employee.name
            logger.debug(f"Login successful as {session['role']}")
            
            if employee.role == 'manager':
                return redirect(url_for('manager_dashboard'))
            elif employee.role == 'backup':
                return redirect(url_for('backup_dashboard'))
            elif employee.role == 'admin':
                return redirect(url_for('admin_dashboard'))  # Add this line
            else:
                return redirect(url_for('employee_dashboard'))
        flash('Invalid login credentials!', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')
            
@app.route('/admin-dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))
    
    # You can add admin-specific data here
    employees = Employee.query.all()
    managers = Employee.query.filter_by(role='manager').all()
    
    return render_template('admin_dashboard.html', 
                          employees=employees, 
                          managers=managers)


@app.route('/admin/assign-designation', methods=['GET'])
def admin_assign_designation_view():
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    employees = Employee.query.all()
    return render_template('admin_assign_designation.html', employees=employees)

@app.route('/assign-designation/<int:employee_id>', methods=['POST'])
def assign_designation(employee_id):
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    designation = request.form.get('designation')
    employee = Employee.query.get_or_404(employee_id)

    if designation:
        employee.designation = designation
        db.session.commit()
        # ✅ Notify employee via email
        notify_employee_after_assignment(employee)
        flash(f"Designation assigned successfully to {employee.name}.", "success")
    else:
        flash("Please enter a valid designation.", "warning")

    return redirect(url_for('admin_assign_designation_view'))

@app.route('/bulk-assign-designation', methods=['POST'])
def bulk_assign_designation():
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    designation = request.form.get('designation')
    employee_ids = request.form.getlist('employee_ids')

    if not designation:
        flash("Please enter a valid designation.", "warning")
        return redirect(url_for('admin_assign_designation_view'))

    if not employee_ids:
        flash("Please select at least one employee.", "warning")
        return redirect(url_for('admin_assign_designation_view'))

    count = 0
    for emp_id in employee_ids:
        employee = Employee.query.get(emp_id)
        if employee:
            employee.designation = designation
            count += 1

    db.session.commit()
    # ✅ Notify employee via email
    notify_employee_after_assignment(employee)
    flash(f"Designation assigned successfully to {count} employees.", "success")
    return redirect(url_for('admin_assign_designation_view'))

@app.route('/assign_roles', methods=['GET', 'POST'])

def assign_roles_view():
    employees = Employee.query.all()
    
    if request.method == 'POST':
        employee_id = request.form.get('employee_id')
        new_role = request.form.get('role')

        employee = Employee.query.get(employee_id)
        if employee:
            employee.role = new_role
            db.session.commit()
            # ✅ Notify employee via email
            notify_employee_after_assignment(employee)
            flash('Role updated successfully.', 'success')
        else:
            flash('Employee not found.', 'danger')

        return redirect(url_for('assign_roles_view'))

    return render_template('assign_roles.html', employees=employees)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = Employee.query.filter_by(email=email).first()
        
        if not user:
            flash('No account found with that email.', 'danger')
            return redirect(url_for('forgot_password'))

        token = generate_reset_token(user.id)
        send_reset_email(user.email, token)
        flash('Password reset instructions sent to your email.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user_id = verify_reset_token(token)
    if not user_id:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('forgot_password'))

    user = Employee.query.get(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        pwd = request.form['password']
        pwd_confirm = request.form['confirm_password']
        if pwd != pwd_confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))

        user.set_password(pwd)
        db.session.commit()
        flash('Your password has been reset! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/backup-login', methods=['GET', 'POST'])
def backup_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        employee = Employee.query.filter_by(email=email).first()

        if employee and employee.role != 'manager' and employee.check_password(password):
            session['user_id'] = employee.id
            session['role'] = 'backup'
            session['email'] = employee.email
            logger.debug(f"Login successful as backup {employee.name}")
            return redirect(url_for('backup_dashboard'))

        flash('Invalid backup login credentials.', 'danger')
        return redirect(url_for('backup_login'))

    return render_template('backup_login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    managers = Employee.query.filter_by(role='manager').all()  # for dropdown

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        contact_number = request.form['contact_number']
        password = request.form['password']
        manager_id = request.form.get('manager_id')

        # Email validation
        if not (email.endswith('@360digitmg.com') or email.endswith('@aispry.com')):
            flash('Email must end with @360digitmg.com or @aispry.com', 'danger')
            return redirect(url_for('register'))

        # Password validation
        password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(password_regex, password):
            flash('Password must be strong: 1 uppercase, 1 lowercase, 1 number, 1 special char.', 'danger')
            return redirect(url_for('register'))

        # Contact number validation
        if not re.match(r'^\d{10}$', contact_number):
            flash('Contact number must be exactly 10 digits.', 'danger')
            return redirect(url_for('register'))

        # Email existence check
        if Employee.query.filter_by(email=email).first():
            flash('Email already registered!', 'warning')
            return redirect(url_for('register'))

        # Create new user
        new_user = Employee(
            name=name,
            email=email,
            contact_number=contact_number,
            manager_id=manager_id
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        # ✅ Notify all admins
        notify_admins_of_new_registration(name, email)

        flash('Registration successful, please log in!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', managers=managers)

@app.route('/employee-dashboard')
def employee_dashboard():
    employee_id = session.get('user_id')
    employee = Employee.query.get(employee_id)

    annual_limit = 24  # total allowed casual leaves per year
    current_year = datetime.now().year

    # Get current year's leaves
    current_year_start = datetime(current_year, 1, 1).date()
    current_year_end = datetime(current_year, 12, 31).date()

    # Only count approved leaves for consistency
    approved_leaves = LeaveRequest.query.filter_by(
        employee_id=employee_id,
        status='Approved'
    ).filter(
        LeaveRequest.start_date >= current_year_start,
        LeaveRequest.start_date <= current_year_end
    ).all()

    # Filter casual leaves for quota calculations
    approved_casual_leaves = [leave for leave in approved_leaves if leave.leave_type == 'Casual Leave']

    # Calculate total used leaves (excluding Sundays) - for ALL approved leave types
    used_leaves = 0
    for leave in approved_leaves:
        used_leaves += calculate_leave_days_excluding_sundays(leave.start_date, leave.end_date)

    # Calculate used casual leaves (for quota tracking)
    used_casual_leaves = 0
    for leave in approved_casual_leaves:
        used_casual_leaves += calculate_leave_days_excluding_sundays(leave.start_date, leave.end_date)

    remaining_casual_leaves = annual_limit - used_casual_leaves

    # Quarterly usage - only for casual leaves
    quarterly_usage = defaultdict(int)
    for leave in approved_casual_leaves:
        quarter = (leave.start_date.month - 1) // 3 + 1
        days = calculate_leave_days_excluding_sundays(leave.start_date, leave.end_date)
        quarterly_usage[quarter] += days
    quarterly_usage = dict(sorted(quarterly_usage.items()))

    # Monthly usage - only for casual leaves
    monthly_usage = defaultdict(int)
    for leave in approved_casual_leaves:
        month = leave.start_date.month
        days = calculate_leave_days_excluding_sundays(leave.start_date, leave.end_date)
        monthly_usage[month] += days
    monthly_usage = dict(sorted(monthly_usage.items()))

    # Month name mapping
    month_name = {
        1: 'January', 2: 'February', 3: 'March',
        4: 'April', 5: 'May', 6: 'June',
        7: 'July', 8: 'August', 9: 'September',
        10: 'October', 11: 'November', 12: 'December'
    }

    # Get all leave types for display
    leave_types = {}
    for leave in approved_leaves:
        if leave.leave_type not in leave_types:
            leave_types[leave.leave_type] = 0
        leave_types[leave.leave_type] += calculate_leave_days_excluding_sundays(leave.start_date, leave.end_date)

    return render_template(
        'employee_dashboard.html',
        employee=employee,
        annual_limit=annual_limit,
        used_leaves=used_leaves,  # Total of all approved leaves
        used_casual_leaves=used_casual_leaves,  # Only casual leaves
        remaining_leaves=remaining_casual_leaves,  # Remaining casual leaves
        quarterly_usage=quarterly_usage,
        monthly_usage=monthly_usage,
        month_name=month_name,
        current_year=current_year,
        leave_types=leave_types  # Breakdown by leave type
    )

@app.route('/manager-dashboard', methods=['GET'])
def manager_dashboard():
    # Ensure the user is a manager
    manager_id = session.get('user_id')
    manager = Employee.query.filter_by(id=manager_id, role='manager').first()

    if not manager:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    # Get all leave requests under this manager
    leave_requests = LeaveRequest.query.join(Employee).filter(Employee.manager_id == manager_id).order_by(LeaveRequest.start_date.desc()).all()

    # Get supervised employees
    employees_under_manager = Employee.query.filter_by(manager_id=manager_id).all()

    # Get unique leave types for dropdown
    leave_types = sorted(set(leave.leave_type for leave in leave_requests if leave.leave_type))

    # Get unique employee names for dropdown
    employee_names = sorted(set(leave.employee.name for leave in leave_requests if leave.employee and leave.employee.name))

    # Add days_requested excluding Sundays to each leave request
    for leave in leave_requests:
        leave.days_requested = calculate_leave_days_excluding_sundays(leave.start_date, leave.end_date)

    return render_template(
        'manager_dashboard.html',
        leave_requests=leave_requests,
        employees_under_manager=employees_under_manager,
        leave_types=leave_types,
        employee_names=employee_names,
        current_year=datetime.now().year
    )

def send_leave_request_email(manager_email, employee_name, start_date, end_date, leave_type, reason, leave_id):
    try:
        logger.info(f"📨 Attempting to send leave request email to manager: {manager_email}")

        # URL generation for approval/rejection actions
        approve_url = url_for('handle_leave', request_id=leave_id, action='approve', _external=True)
        reject_url = url_for('handle_leave', request_id=leave_id, action='reject', _external=True)
        dashboard_url = url_for('manager_dashboard', _external=True)

        logger.info(f"🔗 Approve URL: {approve_url}")
        logger.info(f"🔗 Reject URL: {reject_url}")

        msg = Message(
            subject=f'Leave Request from {employee_name} - Action Required',
            recipients=[manager_email],
            html=f"""
            <html>
            <body>
                <h2>Leave Request Pending Approval</h2>
                <p><strong>{employee_name}</strong> has requested leave:</p>
                <ul>
                    <li><strong>From:</strong> {start_date.strftime('%d %b, %Y')}</li>
                    <li><strong>To:</strong> {end_date.strftime('%d %b, %Y')}</li>
                    <li><strong>Leave Type:</strong> {leave_type}</li>
                    <li><strong>Reason:</strong> {reason}</li>
                </ul>
                
                <p>Please take action:</p>
                <p>
                    <a href="{approve_url}" style="background-color: #4CAF50; color: white; padding: 10px 15px; text-decoration: none; margin-right: 10px;">Approve</a>
                    <a href="{reject_url}" style="background-color: #f44336; color: white; padding: 10px 15px; text-decoration: none;">Reject</a>
                </p>
                
                <p>Or visit your <a href="{dashboard_url}">Manager Dashboard</a> for full details.</p>
                
                <p>Thanks,<br>Leave Management System</p>
            </body>
            </html>
            """
        )

        logger.info("🚀 Sending email to manager...")
        mail.send(msg)
        logger.info(f"✅ Email sent successfully to manager: {manager_email}")
        return True

    except Exception as e:
        logger.error(f"❌ Failed to send manager email to {manager_email}: {str(e)}")
        traceback.print_exc()
        return False

def delete_expired_pending_leaves():
    today = datetime.today().date()
    expired_leaves = LeaveRequest.query.filter(
        LeaveRequest.status == 'Pending',
        LeaveRequest.end_date < today
    ).all()

    for leave in expired_leaves:
        db.session.delete(leave)
    db.session.commit()
    
@app.route('/backup-dashboard')
def backup_dashboard():
    if session.get('role') != 'backup':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    backup_email = session.get('email')
    if not backup_email:
        flash("No email found in session.", "danger")
        return redirect(url_for('login'))

    # Get all leave requests where this user is the assigned backup (internal employee) and not yet acknowledged
    pending_leaves = LeaveRequest.query.filter_by(
        backup_email=backup_email,
        backup_is_employee=True,
        backup_acknowledged=False
    ).all()
    
    # Add days count excluding Sundays to each leave request
    for leave in pending_leaves:
        leave.days_requested = calculate_leave_days_excluding_sundays(leave.start_date, leave.end_date)

    return render_template('backup_dashboard.html', pending_leaves=pending_leaves)

@app.route('/acknowledge_backup/<int:leave_id>', methods=['POST'])
def acknowledge_backup(leave_id):
    if session.get('role') != 'backup':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    leave = LeaveRequest.query.get(leave_id)
    
    if not leave:
        flash("Leave request not found.", "danger")
        return redirect(url_for('backup_dashboard'))
        
    # Verify this user is the assigned backup
    if leave.backup_email != session.get('email'):
        flash("You are not authorized to acknowledge this request.", "danger")
        return redirect(url_for('backup_dashboard'))
    
    leave.backup_acknowledged = True
    db.session.commit()
    
    # Update BackupAcknowledgement record if it exists
    backup_ack = BackupAcknowledgement.query.filter_by(leave_request_id=leave_id).first()
    if backup_ack:
        backup_ack.acknowledged = True
        db.session.commit()
    
    flash("Leave request acknowledged successfully.", "success")
    return redirect(url_for('backup_dashboard'))

@app.route('/handle_leave/<int:request_id>/<action>', methods=['GET', 'POST'])
def handle_leave(request_id, action):
    print(f"[DEBUG] Request method: {request.method}, Action: {action}")
    print(f"[DEBUG] Form data: {request.form}")
    if request.method == 'POST':
        print("Form data:", request.form)
    # Get the leave request from the database
    leave_request = LeaveRequest.query.get_or_404(request_id)
    
    # Check if the leave request is already processed
    if leave_request.status != 'Pending':
        flash('This leave request has already been processed.', 'warning')
        return redirect(url_for('manager_dashboard'))
    
    if action == 'approve':
        # Update leave request status to approved
        leave_request.status = 'Approved'
        # Store manager name instead of ID
        manager_name = session.get('username')
        leave_request.processed_by = manager_name
        leave_request.processed_date = datetime.now()
        
        db.session.commit()
        flash(f'Leave request for {leave_request.employee.name} has been approved.', 'success')
        
        # Send email notification to employee
        send_status_notification(leave_request, 'approved')
        
    elif action == 'reject':
        if request.method == 'POST':
            print("[DEBUG] Form submitted:", request.form)
            rejection_reason = request.form.get('rejection_reason')
            
            if not rejection_reason:
                flash('Rejection reason is required.', 'danger')
                return redirect(url_for('manager_dashboard'))
            
            # Update leave request status to rejected with reason
            leave_request.status = 'Rejected'
            leave_request.rejection_reason = rejection_reason
            # Store manager name instead of ID
            manager_name = session.get('username')
            leave_request.processed_by = manager_name
            leave_request.processed_date = datetime.now()
            
            db.session.commit()
            flash(f'Leave request for {leave_request.employee.name} has been rejected.', 'danger')
            
            # Send email notification to employee
            send_status_notification(leave_request, 'rejected')
        else:
            # If it's a GET request, redirect to dashboard
            # This shouldn't happen with our new modal form implementation
            flash('Please provide a rejection reason through the form.', 'warning')
            return redirect(url_for('manager_dashboard'))
    
    return redirect(url_for('manager_dashboard'))

def send_email(to, subject, body):
    try:
        msg = Message(subject, recipients=[to], body=body)
        mail.send(msg)
        print(f"[Email sent] To: {to}, Subject: {subject}")
    except Exception as e:
        print(f"[Email error] Failed to send to {to}: {str(e)}")

# Helper function for email notifications
def send_status_notification(leave_request, status):
    try:
        employee = leave_request.employee
        # Get manager name directly from the leave request
        manager_name = leave_request.processed_by
        print(f"[DEBUG] Manager name in email: {manager_name}")
        subject = f"Leave Request {status.capitalize()}"
        
        if status == 'approved':
            body = f"""
            Dear {employee.name},
            
            Your leave request for {leave_request.start_date.strftime('%d %b, %Y')} to {leave_request.end_date.strftime('%d %b, %Y')} has been approved by {manager_name}.
            
            Regards,
            HR Department
            """
        else:  # rejected
            body = f"""
            Dear {employee.name},
            
            Your leave request for {leave_request.start_date.strftime('%d %b, %Y')} to {leave_request.end_date.strftime('%d %b, %Y')} has been rejected by {manager_name}.
            
            Reason: {leave_request.rejection_reason}
            
            Regards,
            HR Department
            """
        
        # Your email sending logic here
        send_email(employee.email, subject, body)
        
        # If there's a backup person, notify them as well if the leave was approved
        if status == 'approved' and leave_request.backup_email:
            backup_subject = "Leave Approval Notification - Backup Required"
            backup_body = f"""
            Dear Colleague,
            
            {employee.name} will be on leave from {leave_request.start_date.strftime('%d %b, %Y')} to {leave_request.end_date.strftime('%d %b, %Y')}.
            
            You have been designated as their backup during this period. Please click the link below to acknowledge:
            
            {url_for('acknowledge_backup', leave_id=leave_request.id, _external=True)}
            
            Regards,
            HR Department
            """
            
            send_email(leave_request.backup_email, backup_subject, backup_body)
            
    except Exception as e:
        # Log the error but don't stop the process
        print(f"Error sending notification: {str(e)}")

@app.route('/apply-leave', methods=['GET', 'POST'])
def apply_leave():
    if request.method == 'POST':
        employee_id = session['user_id']
        start_date_str = request.form['start_date']
        end_date_str = request.form['end_date']
        reason = request.form['reason']
        work_assigned = request.form['work_assigned']
        backup_email = request.form['backup_email']
        leave_type = request.form['leave_type']

        start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
        end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()

        requested_days = calculate_leave_days_excluding_sundays(start_date, end_date)
        employee = Employee.query.get(employee_id)
        
        if backup_email.lower() == employee.email.lower():
            flash("You cannot assign yourself as a backup. Please enter another person's email.", "danger")
            return redirect(url_for('apply_leave'))
        # Validate email
        if not re.match(r"[^@]+@[^@]+\.[^@]+", backup_email):
            flash('Please provide a valid email address for backup.', 'danger')
            return redirect(url_for('apply_leave'))

        # Determine if backup is internal
        backup_employee = Employee.query.filter_by(email=backup_email).first()
        backup_is_employee = backup_employee is not None
        acknowledgment_token = None

        if not backup_is_employee:
            acknowledgment_token = secrets.token_urlsafe(32)

        # Leave limits
        if leave_type == "Casual Leave":
            year = start_date.year
            pending_leaves = LeaveRequest.query.filter(
                LeaveRequest.employee_id == employee_id,
                LeaveRequest.leave_type == 'Casual Leave',
                extract('year', LeaveRequest.start_date) == year,
                LeaveRequest.status.in_(['Approved', 'Pending'])
            ).all()

            used_year = sum(calculate_leave_days_excluding_sundays(leave.start_date, leave.end_date) for leave in pending_leaves)

            if used_year + requested_days > 24:
                flash('Casual Leave limit of 24 days per year exceeded.', 'danger')
                return redirect(url_for('apply_leave'))

            quarter = (start_date.month - 1) // 3 + 1
            months_in_quarter = [3 * quarter - 2, 3 * quarter - 1, 3 * quarter]
            quarter_leaves = LeaveRequest.query.filter(
                LeaveRequest.employee_id == employee_id,
                LeaveRequest.leave_type == 'Casual Leave',
                extract('year', LeaveRequest.start_date) == year,
                extract('month', LeaveRequest.start_date).in_(months_in_quarter),
                LeaveRequest.status.in_(['Approved', 'Pending'])
            ).all()

            used_quarter = sum(calculate_leave_days_excluding_sundays(leave.start_date, leave.end_date) for leave in quarter_leaves)
            if used_quarter + requested_days > 6:
                flash('Casual Leave limit of 6 days per quarter exceeded.', 'danger')
                return redirect(url_for('apply_leave'))

        # Create leave request
        new_request = LeaveRequest(
            employee_id=employee_id,
            start_date=start_date,
            end_date=end_date,
            reason=reason,
            leave_type=leave_type,
            work_assigned=work_assigned,
            status='Pending',
            backup_email=backup_email,
            backup_is_employee=backup_is_employee,
            backup_acknowledged=False,
            acknowledgment_token=acknowledgment_token
        )

        db.session.add(new_request)
        db.session.commit()

        # Backup acknowledgment tracking
        if backup_is_employee:
            # Add acknowledgment record
            backup_ack = BackupAcknowledgement(
                leave_request_id=new_request.id,
                backup_employee_id=backup_employee.id,
                acknowledged=False
            )
            db.session.add(backup_ack)
            db.session.commit()

            # Send internal backup email
            send_internal_backup_email(
                backup_email,
                employee.name,
                start_date,
                end_date,
                work_assigned
            )

        else:
            # Send external email with token
            send_acknowledgement_email(
                backup_email,
                employee.name,
                start_date,
                end_date,
                token=acknowledgment_token,
                leave_id=new_request.id,
                work_assigned=work_assigned
            )

        # Notify Manager
        try:
            manager = Employee.query.filter_by(id=employee.manager_id, role='manager').first()
            if manager:
                send_leave_request_email(
                    manager.email,
                    employee.name,
                    start_date,
                    end_date,
                    leave_type,
                    reason,
                    new_request.id
                )
        except Exception as e:
            logger.error(f"❌ Failed to notify manager: {e}")
            traceback.print_exc()

        flash("Leave request submitted successfully.", "success")
        return redirect(url_for('employee_dashboard'))

    return render_template('apply_leave.html')


def generate_token():
    """Generate a secure random token for backup acknowledgment"""
    return secrets.token_urlsafe(32)

def send_acknowledgement_email(backup_email, employee_name, start_date, end_date, token, leave_id, work_assigned):
    try:
        logger.info(f"📧 Attempting to send acknowledgement email to backup: {backup_email}")

        # Create the acknowledgment URL
        acknowledgment_url = url_for(
            'external_backup_acknowledgment', 
            token=token, 
            leave_id=leave_id, 
            _external=True
        )

        logger.info(f"🔗 Acknowledgment URL: {acknowledgment_url}")

        msg = Message(
    subject=f'Backup Request from {employee_name} - Acknowledgment Required',
    recipients=[backup_email],
    html=f"""
    <html>
    <body>
        <h2>Leave Request Acknowledgement Required</h2>
        <p><strong>{employee_name}</strong> has designated you as a backup during their absence.</p>
        <p><strong>Leave period:</strong> {start_date.strftime('%d %b, %Y')} to {end_date.strftime('%d %b, %Y')}</p>

        <p><strong>Work assigned:</strong></p>
        <p>{work_assigned}</p>

        <p>Please click below to review and respond to the backup request:</p>
        <p>
            <a href="{acknowledgment_url}" style="background-color: #4CAF50; color: white; padding: 10px 15px; text-decoration: none; border-radius: 4px; margin-right: 10px;">Acknowledge</a>
            <a href="{acknowledgment_url}" style="background-color: #dc3545; color: white; padding: 10px 15px; text-decoration: none; border-radius: 4px;">Reject</a>
        </p>

        <p>Thank you,<br>Leave Management System</p>
    </body>
    </html>
    """
)

        logger.info("🚀 Sending email to backup...")
        mail.send(msg)
        logger.info(f"✅ Email sent successfully to backup: {backup_email}")
        return True

    except Exception as e:
        logger.error(f"❌ Failed to send backup email to {backup_email}: {str(e)}")
        traceback.print_exc()
        return False

def send_internal_backup_email(backup_email, employee_name, start_date, end_date, work_assigned):
    try:
        dashboard_url = url_for('backup_dashboard', _external=True)
        msg = Message(
            subject=f'Backup Assigned: {employee_name} Leave Request',
            recipients=[backup_email],
            html=f"""
            <p><strong>{employee_name}</strong> has submitted a leave request from <strong>{start_date.strftime('%d %b, %Y')}</strong> to <strong>{end_date.strftime('%d %b, %Y')}</strong>.</p>
            <p><strong>Work Assigned:</strong><br>{work_assigned}</p>
            <p>Please respond in the Backup Dashboard:</p>
            <a href="{dashboard_url}" style="padding: 10px 15px; background: #28a745; color: #fff; text-decoration: none; border-radius: 5px;">Open Backup Dashboard</a>
            """
        )
        mail.send(msg)
    except Exception as e:
        logger.error(f"❌ Error sending internal backup email: {e}")
  

def notify_admins_of_new_registration(employee_name, employee_email):
    try:
        # Fetch all admins from the Employee table
        admins = Employee.query.filter_by(role='admin').all()
        if not admins:
            logger.warning("No admins found to notify.")
            return

        # Build recipient list
        recipients = [admin.email for admin in admins if admin.email]

        admin_dashboard_url = url_for('admin_dashboard', _external=True)

        msg = Message(
            subject="New Employee Registered",
            recipients=recipients,
            html=f"""
            <p>Hello Admin,</p>
            <p><strong>{employee_name}</strong> (<a href="mailto:{employee_email}">{employee_email}</a>) has successfully registered in the Leave Management System.</p>
            <p>Please review and assign their role, manager, or designation if required.</p>

            <p>
                <a href="{admin_dashboard_url}" style="background-color: #007bff; color: white; padding: 10px 16px; text-decoration: none; border-radius: 5px;">Go to Admin Dashboard</a>
            </p>

            <p>Regards,<br>Leave Management System</p>
            """
        )

        mail.send(msg)
        logger.info("✅ Admins notified of new registration.")
    except Exception as e:
        logger.error(f"❌ Failed to send registration email to admins: {str(e)}")

def notify_employee_after_assignment(employee):
    try:
        login_url = url_for('login', _external=True)

        msg = Message(
            subject="Access Granted: You Can Now Apply for Leave",
            recipients=[employee.email],
            html=f"""
            <p>Hello {employee.name},</p>
            <p>Your access has been updated by the admin. You now have the following:</p>
            <ul>
                <li><strong>Role:</strong> {employee.role.capitalize()}</li>
                <li><strong>Designation:</strong> {employee.designation or 'N/A'}</li>
                <li><strong>Manager:</strong> {employee.manager.name if employee.manager else 'Not Assigned'}</li>
            </ul>
            <p>You can now log in to the Leave Management System and submit leave requests.</p>

            <p>
                <a href="{login_url}" style="padding: 10px 15px; background: #28a745; color: #fff; text-decoration: none; border-radius: 5px;">
                    Go to Login
                </a>
            </p>

            <p>Thanks,<br>Leave Management System</p>
            """
        )
        mail.send(msg)
        logger.info(f"✅ Employee {employee.email} notified after admin assignment.")
    except Exception as e:
        logger.error(f"❌ Failed to notify employee {employee.email}: {str(e)}")


@app.route('/external-backup-acknowledgment/<token>/<int:leave_id>', methods=['GET', 'POST'])
def external_backup_acknowledgment(token, leave_id):
    leave = LeaveRequest.query.get_or_404(leave_id)

    if leave.acknowledgment_token != token:
        flash("Invalid acknowledgment link.", "danger")
        return redirect(url_for('home'))

    if leave.backup_acknowledged:
        flash("This leave request has already been acknowledged.", "info")
        return render_template('external_acknowledgment_confirmation.html', leave=leave, already_acknowledged=True)

    employee = Employee.query.get(leave.employee_id)
    leave.days_requested = calculate_leave_days_excluding_sundays(leave.start_date, leave.end_date)

    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == "Acknowledge":
            leave.backup_acknowledged = True
            leave.status = "Pending"  # or retain the current status
            db.session.commit()
            flash("You have acknowledged the leave request.", "success")
            return render_template('external_acknowledgment_confirmation.html', leave=leave, employee=employee, acknowledged=True)

        elif action == "Reject":
            leave.status = "Rejected by Backup"
            db.session.commit()
            flash("You have rejected the leave request.", "warning")
            
            
            return render_template('external_acknowledgment_confirmation.html', leave=leave, employee=employee, rejected=True)

    return render_template('external_acknowledgment.html', leave=leave, employee=employee)


def send_leave_email(email, leave_status, leave_id, rejection_reason=None):
    subject = f"Leave Request {leave_status.capitalize()}"
    
    if leave_status == 'acknowledged':
        body = f"Dear Employee,\n\nYour leave request with ID {leave_id} has been acknowledged."
    elif leave_status == 'rejected':
        body = f"Dear Employee,\n\nYour leave request with ID {leave_id} has been rejected. Reason: {rejection_reason}"
    else:
        print(f"Invalid leave_status: {leave_status}")
        return  # Don't try to send

    if not email:
        print("No recipient email provided.")
        return

    msg = Message(subject, recipients=[email])
    msg.body = body

    try:
        mail.send(msg)
        print(f"Email sent to {email} with subject '{subject}'")
    except Exception as e:
        print(f"Error sending email: {e}")

@app.route('/reject-acknowledgement/<token>', methods=['POST'])
def external_reject(token):
    leave_request = LeaveRequest.query.filter_by(acknowledgment_token=token).first()
    if not leave_request:
        flash("Invalid or expired token.", "danger")
        return redirect(url_for('home'))

    if leave_request.backup_acknowledged:
        flash("You have already acknowledged this request.", "info")
        return redirect(url_for('home'))

    leave_request.backup_acknowledged = False
    leave_request.status = 'Rejected by Backup'
    db.session.commit()

    flash("Leave request has been rejected.", "warning")
    return redirect(url_for('home'))

@app.route('/backup-reject/<int:leave_id>', methods=['POST'])
def reject_backup(leave_id):
    leave = LeaveRequest.query.get_or_404(leave_id)
    reason = request.form.get('rejection_reason')
    employee = Employee.query.get(leave.employee_id)

    if not reason:
        flash("Rejection reason is required.", "danger")
        return redirect(url_for('backup_dashboard'))

    leave.status = 'Rejected by Backup'
    leave.comment = reason
    leave.backup_acknowledged = False
    db.session.commit()

    # ✅ Send rejection email to employee
    try:
        msg = Message(
            subject="Leave Request Rejected by Backup",
            recipients=[employee.email],
            html=f"""
            <p>Hi {employee.name},</p>
            <p>Your leave request from <strong>{leave.start_date.strftime('%d %b, %Y')}</strong> to <strong>{leave.end_date.strftime('%d %b, %Y')}</strong> was <strong>rejected by your backup</strong>.</p>
            <p><strong>Reason:</strong> {reason}</p>
            <p>Please assign another backup and re-submit the request.</p>
            <p>Regards,<br>Leave Management System</p>
            """
        )
        mail.send(msg)
    except Exception as e:
        logger.error(f"Failed to send rejection email to {employee.email}: {str(e)}")

    flash("Leave request rejected and employee notified via email.", "warning")
    return redirect(url_for('backup_dashboard'))

@app.route('/approve-leave/<int:leave_id>', methods=['POST'])
def approve_leave(leave_id):
    if session.get('role') != 'manager':
        return redirect(url_for('login'))

    leave = LeaveRequest.query.get_or_404(leave_id)

    if not leave.backup_acknowledged:
        flash("Backup has not yet acknowledged this leave request.", "warning")
        return redirect(url_for('manager_dashboard'))

    if leave.status != 'Pending':
        flash("This leave has already been processed.", "info")
        return redirect(url_for('manager_dashboard'))

    employee = leave.employee

    leave_days = calculate_leave_days_excluding_sundays(leave.start_date, leave.end_date)

    if leave.leave_type == 'Casual Leave':
        # --- Monthly, Quarterly, and Annual Limits ---
        month = leave.start_date.month
        year = leave.start_date.year

        # Get leaves in the same year and type
        leaves_this_year = LeaveRequest.query.filter_by(
            employee_id=employee.id,
            leave_type='Casual Leave',
            status='Approved'
        ).filter(
            LeaveRequest.start_date.between(f'{year}-01-01', f'{year}-12-31')
        ).all()

        total_approved = 0
        month_count = 0
        quarter_count = 0

        for l in leaves_this_year:
            days = calculate_leave_days_excluding_sundays(l.start_date, l.end_date)
            total_approved += days
            if l.start_date.month == month:
                month_count += days
            if ((l.start_date.month - 1) // 3) == ((month - 1) // 3):
                quarter_count += days

        if total_approved + leave_days > 24:
            flash("Leave exceeds annual casual leave quota (24 days).", "danger")
            return redirect(url_for('manager_dashboard'))

        if month_count + leave_days > 2:
            flash("Leave exceeds monthly casual leave quota (2 days).", "danger")
            return redirect(url_for('manager_dashboard'))

        if quarter_count + leave_days > 6:
            flash("Leave exceeds quarterly casual leave quota (6 days).", "danger")
            return redirect(url_for('manager_dashboard'))

    leave.status = 'Approved'
    db.session.commit()

    flash("Leave request approved.", "success")
    return redirect(url_for('manager_dashboard'))

@app.route('/leave-history')
def leave_history():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    employee = Employee.query.get(session['user_id'])

    if employee:
        # Fetch leave requests ordered by start_date (most recent first)
        requests = LeaveRequest.query.filter_by(employee_id=employee.id).order_by(LeaveRequest.start_date.desc()).all()
        
        # Calculate working days (excluding Sundays) for each request
        for request in requests:
            request.working_days = calculate_leave_days_excluding_sundays(request.start_date, request.end_date)
    else:
        requests = []

    return render_template('leave_history.html', employee=employee, requests=requests)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin/assign-manager', methods=['GET'])
def assign_manager_view():
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    employees = Employee.query.filter_by(role='employee').all()
    managers = Employee.query.filter_by(role='manager').all()
    return render_template('admin_assign_manager.html', employees=employees, managers=managers)

@app.route('/assign-manager/<int:employee_id>', methods=['POST'])
def assign_manager(employee_id):
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    manager_id = request.form.get('manager_id')
    employee = Employee.query.get_or_404(employee_id)

    if manager_id:
        employee.manager_id = int(manager_id)
        db.session.commit()
        # ✅ Notify employee via email
        notify_employee_after_assignment(employee)
        flash(f"Manager assigned successfully to {employee.name}.", "success")
    else:
        flash("Please select a valid manager.", "warning")

    return redirect(url_for('assign_manager_view'))

@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year}

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
