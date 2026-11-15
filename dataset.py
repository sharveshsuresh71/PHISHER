"""
Generates a synthetic but realistic labeled dataset of phishing and
legitimate ("safe") emails for training/testing the classifier.

Each record has: subject, body, sender, label ('phishing' or 'safe')

Emails are composed from many interchangeable parts (openers, situations,
calls-to-action, threats, sign-offs, sender styles) so the data is varied
instead of a handful of copy-pasted templates. It deliberately contains
*hard negatives* (legit emails that say "urgent", "verify", "password",
or come from real brand domains) and *hard positives* (phishing with no
link, from free-mail, or from a normal-looking .com) so the model has to
learn signals rather than memorise templates.

Generation is deterministic for a given seed and does NOT touch the global
``random`` state.
"""

import random

from features import BRAND_DOMAINS

BRANDS = {
    "PayPal": "paypal", "Apple": "apple", "Microsoft 365": "microsoft",
    "Bank of America": "bank of america", "Netflix": "netflix",
    "Amazon": "amazon", "Chase Bank": "chase", "DHL": "dhl", "IRS": "irs",
    "LinkedIn": "linkedin", "Wells Fargo": "wells fargo", "Google": "google",
    "Facebook": "facebook", "Instagram": "instagram", "Dropbox": "dropbox",
    "Spotify": "spotify", "GitHub": "github", "Zoom": "zoom",
}
BAD_TLDS = ["ru", "tk", "xyz", "info", "click", "top", "cn", "icu", "buzz", "work"]


def _slug(brand):
    return BRANDS[brand].replace(" ", "")


def _official(brand):
    return BRAND_DOMAINS[BRANDS[brand]][0]


def _leet(s):
    return s.replace("l", "1", 1) if "l" in s else s.replace("o", "0", 1)


# ======================================================================
# PHISHING
# ======================================================================
P_OPENERS = [
    "Dear valued customer,", "Dear {brand} user,", "Dear Customer,", "Hello,",
    "ATTENTION!", "Dear account holder,", "Hi,", "Dear member,", "",
    "Attention {brand} customer:",
]
# kind -> (subjects, body sentences)
P_SITUATIONS = {
    "suspend": (
        ["Urgent: Your {brand} account has been suspended",
         "Action Required: Verify your {brand} account now",
         "{brand}: Confirm your identity to avoid account closure",
         "Your {brand} account is restricted"],
        ["We detected unusual activity on your {brand} account and it has been temporarily limited.",
         "Your {brand} account has been suspended due to unauthorized access attempts.",
         "Our security system flagged your {brand} account for suspicious behaviour."],
    ),
    "password": (
        ["Your {brand} password will expire in 24 hours",
         "Password expiration notice - {brand}",
         "Reset your {brand} password now"],
        ["Your {brand} password is about to expire.",
         "Your {brand} account password has expired and must be changed.",
         "Our records show your {brand} login credentials are out of date."],
    ),
    "alert": (
        ["Security Alert: Unusual sign-in activity on your {brand} account",
         "New sign-in from unknown device - {brand}",
         "{brand} security notification"],
        ["We noticed a login attempt from an unrecognized device located in {city}.",
         "Someone tried to sign in to your {brand} account from {city}.",
         "A new device in {city} accessed your {brand} account."],
    ),
    "prize": (
        ["You have won a {brand} gift card! Claim now",
         "Congratulations! {brand} reward waiting",
         "Winner notification - {brand} loyalty draw"],
        ["Congratulations! You have been selected to receive a special {brand} reward.",
         "You are the lucky winner of our {brand} anniversary giveaway.",
         "Your {brand} customer survey earned you a free gift card."],
    ),
    "billing": (
        ["Invoice attached - payment overdue - {brand}",
         "Re: Refund pending - verify your {brand} billing details",
         "Payment failed - update your {brand} billing information"],
        ["Your recent invoice of ${amount} could not be processed.",
         "We were unable to charge your card for ${amount}. Your {brand} subscription will be cancelled.",
         "A refund of ${amount} is pending, but we need to confirm your billing details first."],
    ),
    "parcel": (
        ["Your {brand} package could not be delivered",
         "Delivery failed - action required",
         "Redelivery fee required for your parcel"],
        ["Your parcel could not be delivered due to an incomplete address.",
         "We attempted to deliver your package but nobody was home. A small redelivery fee is required.",
         "Your shipment is on hold at our depot pending address confirmation."],
    ),
    "mailbox": (
        ["Your mailbox is almost full", "Dear user, mail storage limit reached",
         "Webmail account deactivation notice"],
        ["Your mailbox storage is 99% full and you will stop receiving new mail.",
         "Your email account will be deactivated unless you validate it today.",
         "Incoming messages are being blocked because your quota is exceeded."],
    ),
    "tax": (
        ["Tax refund notification", "You are eligible for a refund of ${amount}",
         "Final notice: outstanding tax payment"],
        ["After the last annual calculation we determined you are eligible for a tax refund of ${amount}.",
         "Our records show an unpaid balance on your account. Legal action may follow.",
         "To receive your refund you must submit your bank details."],
    ),
    "document": (
        ["Shared document: Q{q} salary review.pdf", "You have a new secure message",
         "Please review and sign - {brand} document"],
        ["A confidential document has been shared with you. Sign in with your email password to view it.",
         "You received a secure fax. Log in to download the attachment.",
         "Please review and e-sign the attached agreement today."],
    ),
    "crypto": (
        ["Double your Bitcoin - limited time", "Your wallet needs verification",
         "Exclusive crypto airdrop for {brand} users"],
        ["Send 0.1 BTC to the address below and receive 0.2 BTC back instantly.",
         "Your crypto wallet has been flagged. Validate your seed phrase to restore access.",
         "Claim your free tokens before the airdrop ends tonight."],
    ),
    "job": (
        ["Job offer - work from home, $ {amount}/week", "Your application has been approved",
         "Quick part-time position available"],
        ["We reviewed your resume and want to hire you immediately. No experience needed, earn ${amount} per week.",
         "Congratulations, you are hired! Send your bank account number and SSN so we can set up payroll.",
         "Start today - you only need to purchase gift cards for office supplies and we will reimburse you."],
    ),
}
P_CTAS = [
    "Please verify your identity immediately by clicking the link below:",
    "Click here to restore access:", "Log in now to confirm your details:",
    "Confirm your information within 24 hours:", "Act now and secure your account:",
    "Update your payment information here:", "Click here to claim your prize:",
    "Follow the link below to continue:", "Sign in to review the activity:",
]
P_THREATS = [
    "Failure to respond within 24 hours will result in permanent suspension of your account.",
    "This is your final warning.", "Your account will be locked in 12 hours if no action is taken.",
    "Do not ignore this message, your account security depends on it.",
    "Offer expires soon!", "Failure to verify will lead to permanent deletion.", "", "",
    "Act immediately to avoid legal action.",
]
P_CLOSERS = [
    "{brand} Security Team", "Customer Support", "{brand} Account Services",
    "Regards,\nThe {brand} Team", "Billing Department", "Do not reply to this email.", "",
]
P_URLS = [
    "http://192.168.{a}.{b}/secure/login", "http://bit.ly/{tok}", "https://tinyurl.com/{tok}",
    "http://{slug}-verify-account.com/login", "http://secure-{slug}.account-update.info",
    "http://{slug}.com.security-check.ru/verify", "http://{slug}support.verify-user-data.com",
    "http://free-gift-{slug}.click/claim", "https://{slug}-login.{tld}/auth",
    "http://{slug}-secure-{b}.com/update", "https://login.{slug}.{tld}.id-verify.net",
    "http://203.0.{a}.{b}/{slug}/login.php", "https://{slug}.verify-center.com/account",
]
CITIES = ["Moscow, Russia", "Lagos, Nigeria", "Beijing, China", "Kyiv, Ukraine", "an unknown location",
          "Bucharest, Romania", "Jakarta, Indonesia"]

BEC_SUBJECTS = ["Quick favor", "Urgent request", "Re: wire transfer", "Are you at your desk?",
                "Payment needed today", "Confidential - do not share"]
BEC_BODIES = [
    "Hi, are you available? I need you to handle a confidential wire transfer of ${amount} to a new "
    "vendor today. I'm in a meeting so can't call. Reply as soon as you see this.",
    "I need a quick favor. Please purchase 5 gift cards of $200 each and send me the codes. "
    "I will reimburse you later. Keep this between us.",
    "Please update the bank account details for our supplier. The new account number is attached. "
    "Send the payment of ${amount} immediately, it is overdue.",
    "Kindly process the pending invoice of ${amount} to the new bank account below today. "
    "Do not discuss this with anyone, I'm travelling.",
]
BEC_NAMES = ["Michael Brown", "Sarah Collins", "David Kim", "Laura Evans", "Robert Hayes"]


def _typo(rng, text):
    """Light obfuscation seen in real phishing: look-alike characters, odd spacing."""
    if rng.random() < 0.12:
        for a, b in (("o", "0"), ("a", "@"), ("i", "1")):
            if rng.random() < 0.4:
                text = text.replace(a, b, rng.randint(1, 2))
    return text


def generate_phishing_email(rng):
    brand = rng.choice(list(BRANDS))
    slug = _slug(brand)
    fmt = dict(brand=brand, city=rng.choice(CITIES), amount=f"{rng.randint(49, 4999)}.{rng.randint(10, 99)}",
               q=rng.randint(1, 4))

    # ~10%: business-email-compromise (no link, free-mail or lookalike sender)
    if rng.random() < 0.10:
        name = rng.choice(BEC_NAMES)
        subject = rng.choice(BEC_SUBJECTS)
        body = f"{rng.choice(['Hi,', 'Hello,', 'Good morning,'])}\n\n{rng.choice(BEC_BODIES).format(**fmt)}\n\n{name.split()[0]}"
        user = name.lower().replace(" ", ".")
        sender = f"{user}@{rng.choice(['gmail.com', 'outlook.com', 'yahoo.com', 'proton.me', 'mail.com'])}"
        return _typo(rng, subject), body, sender, "phishing"

    kind = rng.choice(list(P_SITUATIONS))
    subjects, texts = P_SITUATIONS[kind]
    subject = rng.choice(subjects).format(**fmt)
    parts = [rng.choice(P_OPENERS).format(**fmt), rng.choice(texts).format(**fmt)]

    url_params = dict(slug=slug, tld=rng.choice(BAD_TLDS), a=rng.randint(1, 250), b=rng.randint(1, 250),
                      tok="".join(rng.choices("abcdefghijkmnpqrstuvwxyz23456789", k=7)))
    has_link = rng.random() > 0.12   # a few phishing mails with no link (callback scams)
    if has_link:
        url = rng.choice(P_URLS).format(**url_params)
        parts += [rng.choice(P_CTAS), url]
        if rng.random() < 0.25:
            parts.append("Alternate link: " + rng.choice(P_URLS).format(**url_params))
    else:
        parts.append(f"Call our support line immediately at 1-800-{rng.randint(200, 999)}-{rng.randint(1000, 9999)}.")
    threat = rng.choice(P_THREATS)
    if threat:
        parts.append(threat)
    closer = rng.choice(P_CLOSERS).format(**fmt)
    if closer:
        parts.append(closer)
    parts = [p for p in parts if p]
    body = "\n\n".join(parts)
    if rng.random() < 0.25:
        body = body.replace("Dear", "DEAR", 1).replace("account", "ACCOUNT", 1)

    r = rng.random()
    if r < 0.30:
        domain = f"{slug}-security.{rng.choice(BAD_TLDS + ['com'])}"
    elif r < 0.50:
        domain = f"{_leet(slug)}.com"                       # typosquat
    elif r < 0.65:
        domain = f"{slug}.{rng.choice(['verify', 'secure', 'account'])}-center.{rng.choice(BAD_TLDS + ['com', 'net'])}"
    elif r < 0.80:
        domain = f"{rng.choice(['mail', 'helpdesk', 'notice', 'service'])}-{rng.choice(['center', 'desk', 'hub'])}."\
                 f"{rng.choice(BAD_TLDS + ['com', 'net'])}"
    elif r < 0.90:
        domain = rng.choice(["gmail.com", "outlook.com", "yahoo.com", "hotmail.com"])
    else:
        domain = f"{slug}.com.{rng.choice(['id-verify', 'check', 'auth'])}.{rng.choice(BAD_TLDS)}"
    sender = f"{rng.choice(['support', 'security', 'noreply', 'alert', 'admin', 'billing'])}@{domain}"
    return _typo(rng, subject), body, sender, "phishing"


# ======================================================================
# SAFE
# ======================================================================
FIRST_NAMES = ["Alex", "Jamie", "Priya", "Sam", "Maria", "Chen", "Omar", "Taylor", "Noah", "Aisha", "Ravi", "Emma"]
COMPANY_DOMAINS = ["company.com", "acme.io", "northwind.org", "initech.com", "globex.co", "studio.design"]
S_GREETINGS = ["Hi team,", "Hello,", "Hi,", "Hey,", "Hi all,", "Good morning,", "Hello everyone,"]
S_SIGNOFFS = ["Thanks,\n{n}", "Best,\n{n}", "Cheers,\n{n}", "Regards,\n{n}", "Talk soon,\n{n}", "{n}"]

WORK = [
    ("Team meeting rescheduled to {t} PM",
     "our meeting has been moved to {t} PM today in conference room B. Please bring your quarterly reports."),
    ("Reminder: Project deadline next Friday",
     "just a reminder that the project deliverables are due next Friday. Let me know if you need more time or help."),
    ("URGENT: staging server is down",
     "the staging server is down and we need to fix it asap before the demo. Can someone take a look immediately? "
     "I've posted the logs in the channel."),
    ("Notes from today's stand-up",
     "attached are the notes from today's stand-up. Please review the action items assigned to you and update the "
     "tracker by end of day."),
    ("Action required: submit your timesheet",
     "please submit your timesheet by Friday noon so payroll can run on time. Thanks for your help."),
    ("Quarterly performance review schedule",
     "reviews will be held during the first two weeks of next month. Please pick a slot in the shared calendar."),
    ("Password policy update for the office wifi",
     "IT will rotate the office wifi password on Monday. Ask the front desk for the new one; do not share it outside the company."),
    ("Invoice #{n} for the design work",
     "please find attached the invoice for last month's design work. Payment terms are net 30 as agreed in our contract."),
    ("Welcome to the team!",
     "we're thrilled to have you join us. Your laptop will be ready on your first day and your manager will walk you through onboarding."),
    ("Budget approval needed for Q{q}",
     "can you approve the attached budget when you get a chance? I need sign-off before the finance review on Thursday."),
]
PERSONAL = [
    ("Lunch tomorrow?", "are you free for lunch tomorrow around noon? I was thinking we could try the new place downtown."),
    ("Happy Birthday!", "happy birthday! Hope you have an amazing day. Let's grab dinner this weekend to celebrate."),
    ("Photos from the trip", "here are the photos from our hiking trip last weekend. The one at the summit is my favourite!"),
    ("Re: weekend plans", "I'm in for Saturday. Can we meet at 6 near the station? I'll bring the board games."),
    ("Can you share the Google Doc?", "I can't open the Google Doc you mentioned. Could you share it with my account when you get a chance?"),
    ("Amazon order mix-up", "my Amazon order arrived with the wrong colour, I'm going to return it this week. Did yours arrive fine?"),
    ("Congratulations!", "congratulations on the new job! I'm so happy for you. Let's celebrate soon."),
]
EDU = [
    ("Course registration confirmation", "this email confirms your registration for CS 401: Machine Learning for the Fall semester. "
                                         "Classes begin September 3rd. Please check the syllabus on the course portal."),
    ("Assignment {n} feedback", "your assignment has been graded. Please see my comments in the portal and come to office hours if you have questions."),
    ("Library book due soon", "the book you borrowed is due next Tuesday. You can renew it online or at the front desk."),
]
NEWSLETTER = [
    ("Your weekly newsletter digest", "here is this week's newsletter with the latest articles on software engineering, "
                                      "product design, and industry trends. Click 'unsubscribe' at the bottom if you no longer wish to receive these."),
    ("This week in tech", "the top stories this week: new chip announcements, an open-source release, and a deep dive on databases."),
    ("Meetup: Python night on Thursday", "join us for lightning talks and pizza. RSVP using the link below, spots are limited."),
]
NEWS_SENDERS = ["newsletter@techcrunch.com", "digest@medium.com", "events@meetup.com", "hello@substack.com", "news@theverge.com"]
NEWS_URLS = ["https://techcrunch.com/newsletter", "https://www.meetup.com/python-night/events/{n}", "https://medium.com/digest",
             "https://theverge.com/tech", ""]

# Legit mails from a real brand: (subject, body) — sent from the official domain with official https links
BRAND_LEGIT = {
    "PayPal": [("You paid ${amt} to {n}", "you sent a payment of ${amt}. View the transaction details in your PayPal activity.")],
    "Apple": [("Your receipt from Apple", "thanks for your purchase. Your receipt for ${amt} is available in your Apple account settings.")],
    "Microsoft 365": [("Your Microsoft 365 subscription renewed", "your subscription has renewed. The payment of ${amt} was successful.")],
    "Amazon": [("Your Amazon order has shipped", "your order #{o} has shipped and should arrive Thursday. Track it in your orders page.")],
    "Netflix": [("New on Netflix this week", "check out new shows and movies added this week. Manage your plan any time in account settings.")],
    "Google": [("Security alert", "a new sign-in to your Google account was detected on a Windows device. If this was you, "
                                  "you don't need to do anything. If not, you can review the activity from your account page.")],
    "GitHub": [("Pull request #{o} merged into main", "your pull request was successfully merged into main. The CI pipeline passed all tests. Great work!")],
    "Spotify": [("Your Spotify Premium receipt", "thanks for your subscription. Your monthly payment of $9.99 was processed successfully.")],
    "Zoom": [("Your Zoom meeting summary", "your meeting 'Q3 Planning' has ended. The recording and summary are available in your account for 30 days.")],
    "LinkedIn": [("You appeared in {o} searches this week", "see who's been looking at your profile and discover new opportunities.")],
    "DHL": [("Your DHL shipment is on its way", "your parcel with tracking number {o} is out for delivery today between 10:00 and 14:00.")],
    "Chase Bank": [("Your statement is ready", "your monthly statement is ready to view. Sign in at chase.com or in the mobile app.")],
    "Bank of America": [("Your statement is available", "your latest eStatement is available. Log in to Online Banking to view it. We'll never ask for your password by email.")],
    "Wells Fargo": [("Account alert: low balance", "your checking balance is below the threshold you set. You can review your account in the mobile app.")],
    "Dropbox": [("{n} shared a folder with you", "a folder was shared with you. Open it from your Dropbox account.")],
    "Facebook": [("You have 3 new notifications", "see what your friends have been up to since your last visit.")],
    "Instagram": [("Your photo got new likes", "your recent post is getting attention. See who liked it in the app.")],
    "IRS": [("Your tax account update", "your online account has a new notice. Sign in to irs.gov to view it. We never request personal details by email.")],
}
# one-time-code / sign-in mails are legit but use "expires" / "verification" wording
OTP_LEGIT = [
    ("Your {brand} verification code", "your verification code is {o}. It expires in 10 minutes. Never share this code with anyone."),
    ("{o} is your {brand} security code", "use this code to finish signing in. It will expire shortly. If you didn't request it, you can ignore this email."),
    ("Your {brand} login code", "enter the code {o} to sign in to your account. The code is valid for 5 minutes."),
]
for _b in ("Google", "Microsoft 365", "GitHub", "Apple", "Amazon", "PayPal", "Dropbox", "LinkedIn", "Zoom", "Netflix", "Spotify"):
    BRAND_LEGIT[_b] = BRAND_LEGIT.get(_b, []) + [(s.replace("{brand}", _b), t.replace("{brand}", _b)) for s, t in OTP_LEGIT]

BRAND_SENDER_PREFIX = ["no-reply", "service", "notifications", "support", "billing", "info"]
BRAND_PATHS = ["account", "activity", "orders", "settings/billing", "help", "dashboard"]


def generate_safe_email(rng):
    name = rng.choice(FIRST_NAMES)
    fmt = dict(t=rng.randint(1, 5), n=rng.randint(100, 999), q=rng.randint(1, 4),
               amt=f"{rng.randint(5, 600)}.{rng.randint(10, 99)}", o=rng.randint(10000, 99999))
    greet = rng.choice(S_GREETINGS)
    sign = rng.choice(S_SIGNOFFS).format(n=name)

    r = rng.random()
    if r < 0.30:  # legit brand email from official domain
        brand = rng.choice(list(BRAND_LEGIT))
        subject, text = rng.choice(BRAND_LEGIT[brand])
        domain = _official(brand)
        subject = subject.format(**{**fmt, "n": name})
        body = f"{rng.choice(['Hi,', 'Hello,', f'Hi {name},'])}\n\n{text.format(**{**fmt, 'n': name})}"
        if rng.random() < 0.75:
            host = domain if rng.random() < 0.5 else f"www.{domain}"
            body += f"\n\nhttps://{host}/{rng.choice(BRAND_PATHS)}"
        body += f"\n\n{rng.choice([brand + ' Team', 'Customer Care', 'The ' + brand + ' Team'])}"
        sender = f"{rng.choice(BRAND_SENDER_PREFIX)}@{domain}"
        return subject, body, sender, "safe"

    if r < 0.60:
        subject, text = rng.choice(WORK)
        domain = rng.choice(COMPANY_DOMAINS)
    elif r < 0.78:
        subject, text = rng.choice(PERSONAL)
        domain = rng.choice(["gmail.com", "outlook.com", "yahoo.com", rng.choice(COMPANY_DOMAINS)])
    elif r < 0.88:
        subject, text = rng.choice(EDU)
        domain = rng.choice(["university.edu", "college.edu", "school.edu"])
    else:
        subject, text = rng.choice(NEWSLETTER)
        sender = rng.choice(NEWS_SENDERS)
        url = rng.choice(NEWS_URLS).format(n=rng.randint(1000, 9999))
        body = f"Hello,\n\n{text[0].upper()}{text[1:]}" + (f"\n\n{url}" if url else "") + "\n\nThe Editorial Team"
        return subject.format(**fmt), body, sender, "safe"

    subject = subject.format(**fmt)
    body = f"{greet}\n\n{text.format(**fmt)[0].upper()}{text.format(**fmt)[1:]}"
    if rng.random() < 0.30:
        body += "\n\n" + rng.choice([
            f"https://{rng.choice(COMPANY_DOMAINS)}/docs/{rng.randint(1, 99)}",
            "https://github.com/company/repo/pull/482",
            "https://company.slack.com/archives/general",
            "https://calendar.google.com/calendar/event",
            "https://zoom.us/j/123456789",
        ])
    body += f"\n\n{sign}"
    sender = f"{name.lower()}@{domain}"
    return subject, body, sender, "safe"


def build_dataset(n_per_class=1000, seed=42):
    """Return a shuffled list of (subject, body, sender, label) tuples with no duplicates."""
    rng = random.Random(seed)
    rows, seen = [], set()
    for gen, label in ((generate_phishing_email, "phishing"), (generate_safe_email, "safe")):
        count, attempts = 0, 0
        while count < n_per_class and attempts < n_per_class * 50:
            attempts += 1
            row = gen(rng)
            key = row[:3]
            if key in seen:
                continue
            seen.add(key)
            rows.append(row)
            count += 1
    rng.shuffle(rows)
    return rows


if __name__ == "__main__":
    import csv
    rows = build_dataset(1000)
    with open("emails_dataset.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["subject", "body", "sender", "label"])
        writer.writerows(rows)
    print(f"Generated {len(rows)} emails -> emails_dataset.csv")
