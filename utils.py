# utils.py
from flask_mail import Message
from flask import current_app, url_for
from extensions import mail  # ✅ Get mail from extensions, not app.py

def send_reset_email(user_email, token):
    reset_link = url_for('reset_password', token=token, _external=True)
    msg = Message(
        subject='Password Reset Request',
        recipients=[user_email],
        html=f"""
        <p>To reset your password, click the link below:</p>
        <p><a href="{reset_link}">Reset Password</a></p>
        <p>If you did not request this, simply ignore this email.</p>
        """
    )
    mail.send(msg)

#def send_email(subject, to, body):
    #with current_app.app_context():
        #msg = Message(subject=subject, recipients=to, body=body, sender=current_app.config['MAIL_USERNAME'])
        #mail.send(msg)

from datetime import datetime
from collections import defaultdict
from models import LeaveRequest
from sqlalchemy import extract

def check_leave_limits(employee_id, start_date, end_date, db):
    current_year = datetime.now().year
    requested_days = (end_date - start_date).days + 1
    start_month = start_date.month
    quarter = (start_month - 1) // 3 + 1

    # Fetch all approved casual leaves of current year
    leaves = LeaveRequest.query.filter_by(
        employee_id=employee_id,
        status='Approved',
        leave_type='Casual Leave'
    ).filter(
        extract('year', LeaveRequest.start_date) == current_year
    ).all()

    monthly_usage = 0
    quarterly_usage = 0
    total_used = 0

    for leave in leaves:
        days = (leave.end_date - leave.start_date).days + 1
        leave_month = leave.start_date.month
        leave_quarter = (leave_month - 1) // 3 + 1

        total_used += days

        if leave_month == start_month:
            monthly_usage += days
        if leave_quarter == quarter:
            quarterly_usage += days

    # New totals if this leave is approved
    new_monthly = monthly_usage + requested_days
    new_quarterly = quarterly_usage + requested_days
    new_total = total_used + requested_days

    return {
        "valid": new_monthly <= 2 and new_quarterly <= 6 and new_total <= 24,
        "new_monthly": new_monthly,
        "new_quarterly": new_quarterly,
        "new_total": new_total,
        "requested_days": requested_days
    }

