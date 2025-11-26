import sqlite3
from datetime import datetime

from flask import (
    Blueprint,
    redirect,
    render_template,
    request,
    session,
)
from settings import Settings
from utils.log import Log
from utils.paginate import paginate_query

adminPanelSecurityAuditBlueprint = Blueprint("adminPanelSecurityAudit", __name__)


@adminPanelSecurityAuditBlueprint.route("/admin/security-audit", methods=["GET"])
@adminPanelSecurityAuditBlueprint.route("/adminpanel/security-audit", methods=["GET"])
def adminPanelSecurityAudit():
    """
    Display security audit logs to admin users.
    Shows client access logs, admin login logs, and admin actions.

    Returns:
        Rendered template or redirect
    """
    if "userName" not in session:
        Log.error(
            f"{request.remote_addr} tried to reach security audit panel without being logged in"
        )
        return redirect("/")

    Log.info(f"Admin: {session['userName']} reached security audit admin panel")
    Log.database(f"Connecting to '{Settings.DB_USERS_ROOT}' database")

    connection = sqlite3.connect(Settings.DB_USERS_ROOT)
    connection.set_trace_callback(Log.database)
    cursor = connection.cursor()
    cursor.execute(
        """select role from users where userName = ? """,
        [(session["userName"])],
    )
    role_result = cursor.fetchone()

    if not role_result or role_result[0] != "admin":
        Log.error(
            f"{request.remote_addr} tried to reach security audit panel without being admin"
        )
        connection.close()
        return redirect("/")

    # Get filter parameters
    event_filter = request.args.get("filter", "all")

    # Build query based on filter
    if event_filter == "admin_logins":
        filter_condition = "WHERE event_type LIKE 'admin_login%'"
    elif event_filter == "user_logins":
        filter_condition = "WHERE event_type LIKE 'user_login%'"
    elif event_filter == "admin_actions":
        filter_condition = "WHERE event_type = 'admin_action'"
    elif event_filter == "page_access":
        filter_condition = "WHERE event_type = 'page_access'"
    elif event_filter == "rate_limits":
        filter_condition = "WHERE event_type = 'rate_limit_triggered'"
    else:
        filter_condition = ""

    # Paginate security audit logs
    audit_logs, page, total_pages = paginate_query(
        Settings.DB_USERS_ROOT,
        f"SELECT COUNT(*) FROM security_audit_log {filter_condition}",
        f"SELECT * FROM security_audit_log {filter_condition} ORDER BY timeStamp DESC",
    )

    # Format timestamps
    formatted_logs = []
    for log in audit_logs:
        log_list = list(log)
        try:
            # Convert timestamp (index 9) to readable format
            log_list[9] = datetime.fromtimestamp(log_list[9]).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            # Keep original if conversion fails
            pass
        formatted_logs.append(log_list)
    
    audit_logs = formatted_logs

    connection.close()

    Log.info(f"Rendering adminPanelSecurityAudit.html: filter={event_filter}")

    return render_template(
        "adminPanelSecurityAudit.html",
        audit_logs=audit_logs,
        page=page,
        total_pages=total_pages,
        current_filter=event_filter,
    )
