import re

# suspicious words list
suspicious_words = [
    "urgent", "verify", "suspended", "click here", "act now"
]

# suspicious domain patterns

suspicious_domains = [
    r"paypa1\.com",
    r"secure-login",
    r"free-gift",
    r"update-account"
]

def check_phishing(email_text):
    score = 0

    # check suspicious words
    for word in suspicious_words:
        if word.lower() in email_text.lower():
            score += 1

    # check suspicious links
    links = re.findall(r"http[s]?://\S+", email_text)
    for link in links:
        for domain in suspicious_domains:
            if re.search(domain, link):
                score += 2

    return score

# read email file
with open("sample_emails.txt", "r") as file:
    email_content = file.read()

risk_score = check_phishing(email_content)

print("Phishing Risk Score:", risk_score)

if risk_score >= 3:
    print("⚠️ This email is likely PHISHING")
else:
    print("✅ This email looks SAFE")
