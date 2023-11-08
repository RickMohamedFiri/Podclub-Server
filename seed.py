# seed.py
import secrets
import string
from app import app, db
from models import User, Channel, Messages, GroupMessage, ReportedUser, ReportedMessage, Admin
from datetime import datetime

def seed_database():
    with app.app_context():
        # Create the database tables
        db.create_all()

        # Function to generate a secure verification token
        def generate_verification_token(token_length=10):
            alphabet = string.ascii_letters + string.digits  # Use letters and numbers
            return ''.join(secrets.choice(alphabet) for _ in range(token_length))

        # # Create and add user records
        # user1 = User(user_name='Aleki', email='alexi@gmail.com', password='wordpass', verification_token=generate_verification_token(), role='admin')
        # user2 = User(user_name='Jamex', email='jamex@gmail.com', password='jamojam', verification_token=generate_verification_token(), role='user')
# Create and add user records
        user1 = User(user_name='Aleki',  email='alexi@gmail.com', password='wordpass', verification_token=generate_verification_token(), role='admin')
        user2 = User(user_name='Jamex',  email='jamex@gmail.com', password='jamojam', verification_token=generate_verification_token(), role='user')

        # Add users to the session
        db.session.add_all([user1, user2])
        db.session.commit()

        # Create and add channel records
        channel1 = Channel(name='Channel 1', description='Description 1', user_id=user1.id)
        channel2 = Channel(name='Channel 2', description='Description 2', user_id=user2.id)

        # Add channels to the session
        db.session.add_all([channel1, channel2])
        db.session.commit()

        # Create and add message records
        message1 = Messages(message='Hello, world!', user_id=user1.id, channel_id=channel1.id)
        message2 = Messages(message='Hi there!', user_id=user2.id, channel_id=channel1.id)

        # Add messages to the session
        db.session.add_all([message1, message2])
        db.session.commit()

        # Create and add group message records
        group_message1 = GroupMessage(channel_id=channel1.id, user_id=user1.id)
        group_message2 = GroupMessage(channel_id=channel2.id, user_id=user2.id)

        # Add group messages to the session
        db.session.add_all([group_message1, group_message2])
        db.session.commit()

        # Create and add reported user records
        reported_user1 = ReportedUser(reporting_user_id=user1.id, reported_user_id=user2.id, message_id=message1.id, report_date=datetime.now(), is_banned=True)
        reported_user2 = ReportedUser(reporting_user_id=user2.id, reported_user_id=user1.id, message_id=message2.id, report_date=datetime.now(), is_banned=True)

        # Add reported users to the session
        db.session.add_all([reported_user1, reported_user2])
        db.session.commit()

        # Create and add reported message records
        reported_message1 = ReportedMessage(reporting_user_id=user1.id, user_id=user2.id, message_id=message1.id, report_date=datetime.now(),is_banned= True)  # Provide a valid report_date
        reported_message2 = ReportedMessage(reporting_user_id=user2.id, user_id=user1.id, message_id=message2.id, report_date=datetime.now(),is_banned=True)  # Provide a valid report_date

        # Add reported messages to the session
        db.session.add_all([reported_message1, reported_message2])
        db.session.commit()


        # # Create and add UserReport records
        # user_report1 = UserReport(reporting_user_id=user1.id, reported_user_id=user2.id, reported_content_id=101, action_taken='No action taken')
        # user_report2 = UserReport(reporting_user_id=user2.id, reported_user_id=user1.id, reported_content_id=102, action_taken='Warning issued')

        # # Add UserReport instances to the session
        # db.session.add_all([user_report1, user_report2])
        # db.session.commit()
        # Create and add admin records
        admin1 = Admin(user_id=user1.id, can_ban_users=True, can_delete_channels=True)
        admin2 = Admin(user_id=user2.id, can_ban_users=True, can_delete_channels=False)

        # Add admins to the session
        db.session.add_all([admin1, admin2])
        db.session.commit()

       


if __name__ == '__main__':
    seed_database()