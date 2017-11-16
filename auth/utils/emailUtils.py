import smtplib
from email.mime.text import MIMEText

import conf


def sendMail(to, subject, htmlMsg):
    if conf.emailHost == 'NOEMAIL':
        return
    # TODO: I think we should put this function in a worker thread
    msg = MIMEText(htmlMsg, 'html')

    msg['Subject'] = subject
    msg['From'] = conf.emailUsername
    msg['To'] = to

    s = smtplib.SMTP(conf.emailHost, conf.emailPort)
    if conf.emailTLS:
        s.starttls()
    s.login(conf.emailUsername, conf.emailPasswd)

    x = s.sendmail(conf.emailUsername, [to], msg.as_string())
    s.quit()
