from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
bcrypt = Bcrypt()

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    contact_number = db.Column(db.String(20))
    designation = db.Column(db.String(100))
    role = db.Column(db.String(20), nullable=False, default='employee')

    manager_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=True)
    manager = db.relationship('Employee', remote_side=[id], backref='subordinates')

    def set_password(self, raw_password):
        self.password = bcrypt.generate_password_hash(raw_password).decode('utf-8')

    def check_password(self, raw_password):
        return bcrypt.check_password_hash(self.password, raw_password)

class LeaveRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'))
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Pending')
    reason = db.Column(db.Text, nullable=True)
    leave_type = db.Column(db.String(50), nullable=False)
    backup_email = db.Column(db.String(120))
    backup_acknowledged = db.Column(db.Boolean, default=False)
    acknowledgment_token = db.Column(db.String(64), nullable=True)
    backup_is_employee = db.Column(db.Boolean, default=False)
    work_assigned = db.Column(db.Text, nullable=True)
    rejection_reason = db.Column(db.Text, nullable=True)
    processed_by = db.Column(db.String(100), nullable=True)

    employee = db.relationship('Employee', backref='leave_requests')

class BackupAcknowledgement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    leave_request_id = db.Column(db.Integer, db.ForeignKey('leave_request.id'))
    backup_employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'))
    acknowledged = db.Column(db.Boolean, default=False)

    leave_request = db.relationship('LeaveRequest', backref='backup_acknowledgements')
    backup_employee = db.relationship('Employee')
