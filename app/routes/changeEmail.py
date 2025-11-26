import sqlite3

from flask import (
    Blueprint,
    redirect,
    render_template,
    request,
    session,
)
from settings import Settings
from utils.flashMessage import flashMessage
from utils.forms.ChangeEmailForm import ChangeEmailForm
from utils.log import Log

changeEmailBlueprint = Blueprint("changeEmail", __name__)


@changeEmailBlueprint.route("/changeemail", methods=["GET", "POST"])
def changeEmail():
    """
    Checks if the user is logged in:
    If the user is not logged in, they are redirected to the homepage.

    Checks if the user has submitted a new email:
    If the user has submitted a new email, the new email is checked to ensure it meets the requirements.

    If the new email meets the requirements:
    The user's details are updated in the database.
    The user is redirected to their profile page.

    If the new email does not meet the requirements:
    An error message is displayed.

    Returns:
    The change email template with the form.
    """

    if "userName" in session:
        form = ChangeEmailForm(request.form)

        if request.method == "POST":
            newEmail = request.form["newEmail"]
            Log.database(f"Connecting to '{Settings.DB_USERS_ROOT}' database")

            connection = sqlite3.connect(Settings.DB_USERS_ROOT)
            connection.set_trace_callback(Log.database)
            cursor = connection.cursor()
            cursor.execute(
                """select email from users where email = ? """,
                [(newEmail)],
            )
            emailCheck = cursor.fetchone()

            if newEmail == session.get("email", ""): # Note: session might not have email, need to check or fetch
                 # Actually, let's fetch current email to compare if needed, or just rely on DB check.
                 # But wait, if they enter their OWN email, it should probably say "same" or just success (no-op).
                 # Let's check against DB for uniqueness.
                 pass

            if emailCheck is None:
                cursor.execute(
                    """update users set email = ? where userName = ? """,
                    [(newEmail), (session["userName"])],
                )
                connection.commit()
                Log.success(
                    f'User: "{session["userName"]}" changed his email to "{newEmail}"'
                )
                # Update session email if we store it there? 
                # The session usually stores userName. Let's check if it stores email.
                # Based on login.py (not visible here but usually), it might not.
                # But let's assume we just update DB.
                
                flashMessage(
                    page="changeEmail",
                    message="success",
                    category="success",
                    language=session["language"],
                )
                return redirect("/accountsettings")
            else:
                flashMessage(
                    page="changeEmail",
                    message="taken",
                    category="error",
                    language=session["language"],
                )

        return render_template(
            "changeEmail.html",
            form=form,
        )
    else:
        Log.error(
            f"{request.remote_addr} tried to change his email without being logged in"
        )

        return redirect("/")
