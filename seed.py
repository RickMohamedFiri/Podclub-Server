# seed.py
from app import app, db
from models import User, Channel, Message, GroupMessage, ReportedUser, ReportedMessage, GroupChannel, GroupChatMessage

def seed_database():
    with app.app_context():
        # Create the database tables
        db.create_all()

        # Create and add user records
        user1 = User(first_name='Aleki', last_name='Alex', email='alexi@gmail.com', password='wordpass')
        user2 = User(first_name='Jamex', last_name='Xemas', email='jamex@gmail.com', password='jamojam')

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
        message1 = Message(message='Hello, world!', user_id=user1.id, channel_id=channel1.id)
        message2 = Message(message='Hi there!', user_id=user2.id, channel_id=channel1.id)

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
        reported_user1 = ReportedUser(reporting_user_id=user1.id, reported_user_id=user2.id, message_id=message1.id)
        reported_user2 = ReportedUser(reporting_user_id=user2.id, reported_user_id=user1.id, message_id=message2.id)

        # Add reported users to the session
        db.session.add_all([reported_user1, reported_user2])
        db.session.commit()

        # Create and add reported message records
        reported_message1 = ReportedMessage(reporting_user_id=user1.id, user_id=user2.id, message_id=message1.id)
        reported_message2 = ReportedMessage(reporting_user_id=user2.id, user_id=user1.id, message_id=message2.id)

        # Add reported messages to the session
        db.session.add_all([reported_message1, reported_message2])
        db.session.commit()


        

        # Create and add group channel records
        group_channel1 = GroupChannel(user_id=user1.id, channel_name='Group Channel 1', description='Group Chat 1')
        group_channel2 = GroupChannel(user_id=user2.id, channel_name='Group Channel 2', description='Group Chat 2')

        # Add group channels to the session
        db.session.add_all([group_channel1, group_channel2])
        db.session.commit()

        # Create and add group message records
        group_message3 = GroupChatMessage(channel_id=group_channel1.id, user_id=user1.id, content='Hello from Group Chat 1!')
        group_message4 = GroupChatMessage(channel_id=group_channel2.id, user_id=user2.id, content='Hi from Group Chat 2!')

        # Add group messages to the session
        db.session.add_all([group_message3, group_message4])
        db.session.commit()


        

if __name__ == '__main__':
    seed_database()

