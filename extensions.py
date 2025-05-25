from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate  # ✅ Import Migrate
from flask_mail import Mail

db = SQLAlchemy()
bcrypt = Bcrypt()
migrate = Migrate()  # ✅ Add this
mail = Mail()