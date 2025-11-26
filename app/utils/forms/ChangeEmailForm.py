"""
This file contains class that are used to create ChangeEmailForm for the application.
"""

from wtforms import (
    Form,
    StringField,
    validators,
)


class ChangeEmailForm(Form):
    """
    This class creates a form for changing the email.
    """

    newEmail = StringField(
        "Email",
        [validators.Length(min=6, max=50), validators.Email(), validators.InputRequired()],
    )
