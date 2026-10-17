from analysis_engine import analyze_email_complete

email = """
URGENT

Your Microsoft account has been suspended.
Verify immediately.
http://192.168.1.1/login
"""

result = analyze_email_complete(
    email_text=email,
    attachments=["invoice.pdf.exe"],
    from_email="support@microsoft.com",
    reply_to="fake@gmail.com"
)

print(result)