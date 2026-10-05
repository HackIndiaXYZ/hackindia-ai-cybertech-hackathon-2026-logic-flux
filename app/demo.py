"""Built-in sample emails. They are fed through the real engine, so scores are computed, not hard-coded."""
from datetime import datetime, timezone
from email.utils import format_datetime

KINDS = ("bec", "credential", "ceo", "invoice", "legit")


def _date():
    return format_datetime(datetime.now(timezone.utc))


def demo_email(kind: str) -> bytes:
    d = _date()
    if kind == "bec":
        raw = f"""Received: from mx1.mailhost.net (mx1.mailhost.net [41.22.6.10]) by mail.company.com with ESMTPS; {d}
Received: from edge-relay-09.net (edge-relay-09.net [92.118.4.3]) by mx1.mailhost.net with ESMTP; {d}
Received: from cloud-vps-host.io (unknown [185.212.8.44]) by edge-relay-09.net with ESMTP; {d}
Authentication-Results: mail.company.com; spf=fail smtp.mailfrom=paypa1-support.com; dkim=none; dmarc=fail header.from=paypa1-support.com
From: PayPal Billing Department <accounts@paypa1-support.com>
Reply-To: billing-help@xyzmail.com
Return-Path: <bounce@paypa1-support.com>
To: finance@company.com
Subject: Urgent Invoice Payment Required
Date: {d}
Message-ID: <demo-78291@mail.example>
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body>
<p>Dear Finance Team,</p>
<p>Invoice #88213 is overdue. Please complete the payment immediately to avoid your account being suspended.
This is time sensitive - the wire transfer must be released within 24 hours. Use the updated bank details in the portal below.</p>
<p><a href="http://paypal-secure.account-verify.top/redirect?url=http://185.212.8.44/login">https://www.paypal.com/invoice/pay</a></p>
<p>PayPal Billing Department</p>
</body></html>
"""
    elif kind == "credential":
        raw = f"""Received: from mail-gw.corp-portal-secure.net (mail-gw.corp-portal-secure.net [45.155.205.17]) by mx.company.com with ESMTP; {d}
Authentication-Results: mx.company.com; spf=softfail; dkim=fail; dmarc=fail
From: HR Portal <hr-noreply@corp-portal-secure.net>
To: employee@company.com
Subject: Password Expiry Notice
Date: {d}
Message-ID: <cred-4410@corp-portal-secure.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Your password expires today. Please log in immediately and verify your account to keep access.
Failure to comply will lock your account.

http://company-login.corp-portal-secure.net/signin/verify
"""
    elif kind == "ceo":
        raw = f"""Received: from smtp.freemail-relay.com (smtp.freemail-relay.com [193.46.255.9]) by mx.company.com with ESMTP; {d}
Authentication-Results: mx.company.com; spf=fail; dkim=none; dmarc=fail
From: "Michael Hayes - CEO" <ceo.office@company-exec.co>
Reply-To: michael.hayes.office@gmail.com
To: finance@company.com
Subject: Confidential Wire Transfer
Date: {d}
Message-ID: <ceo-9921@company-exec.co>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Are you available? I'm in a meeting and cannot take calls. I need you to process a confidential wire transfer
today. Please keep this between us. Send the beneficiary bank details confirmation as soon as possible.
"""
    elif kind == "invoice":
        raw = f"""Received: from relay.vendor-invoices.io (relay.vendor-invoices.io [62.204.41.88]) by mx.company.com with ESMTP; {d}
Authentication-Results: mx.company.com; spf=pass; dkim=none; dmarc=none
From: Billing <billing@vendor-invoices.io>
To: accounts@company.com
Subject: Q3 Invoice Attached
Date: {d}
Message-ID: <inv-3321@vendor-invoices.io>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain; charset="utf-8"

Hello, please find our Q3 invoice attached. Open the attachment to view details.
Short link: https://bit.ly/3xQ3inv
--BOUNDARY
Content-Type: text/html; name="Q3-Invoice.html"
Content-Disposition: attachment; filename="Q3-Invoice.html"

<html><body>Loading invoice...</body></html>
--BOUNDARY--
"""
    elif kind == "legit":
        raw = f"""Received: from out.example.org (out.example.org [66.249.84.5]) by mx.company.com with ESMTPS; {d}
Authentication-Results: mx.company.com; spf=pass smtp.mailfrom=example.org; dkim=pass header.d=example.org; dmarc=pass header.from=example.org
From: Example Team <team@example.org>
To: employee@company.com
Subject: Your weekly project digest
Date: {d}
Message-ID: <digest-1@example.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi team, here is the weekly summary of merged pull requests and upcoming milestones.
Notes from Tuesday's planning meeting are in the shared folder. Thanks!
"""
    else:
        raise ValueError(f"unknown demo kind: {kind}")
    return raw.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")


# (kind, minutes_ago) used to seed an empty database; two PayPal-lookalike mails form a "campaign".
SEED_PLAN = [
    ("legit", 480), ("invoice", 330), ("ceo", 200), ("credential", 95),
    ("bec", 40), ("bec", 18),
]
