Leave Management System – Flask Web Application
Developed a robust role-based Leave Management System using Flask, PostgreSQL, SQLAlchemy, and Bootstrap.

Implemented roles such as Admin, Manager, Employee, and Backup with granular access control.

Enabled employees to apply for leaves with real-time validation, auto-calculated working days (excluding Sundays and holidays).

Managers can approve/reject leaves with rejection reasons, and receive automated email notifications.

Introduced backup handling: internal backups are notified via dashboard and email; external backups via acknowledgment links.

Admin can assign roles, managers, and designations, with bulk assignment support and real-time email alerts.

Leave limits enforced based on monthly, quarterly, and annual quotas for Casual Leave.

Integrated email notifications for employees and admins using Flask-Mail.

Deployed the application on an AWS EC2 instance using a secure production-ready environment.
