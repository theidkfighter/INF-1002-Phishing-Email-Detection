import difflib

def loadWhitelist(txtPath):
    # txt file
    try:
        with open(txtPath, "r") as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        print("Dataset Missing")
        return set()
'''     
def loadCSV(csvPath, column_name="name column thing"):
    try:
        df = pd.read_csv(csvPath)
        if column_name not in df.columns:
            print("Column missing in CSV")
            return set()
        return set(df[column_name].dropna().str.lower().str.strip())
    except FileNotFoundError:
        print("Dataset Missing")
        return set()
'''
# commented out risk score for now as it was for testing

def editDistanceCheck(senderEmail, safeDomains):
    senderDomain = senderEmail.split("@")[-1].lower() if "@" in senderEmail else ""

    # suspicious is close match, unknown is totally no close matches in the list
    match = difflib.get_close_matches(senderDomain, safeDomains, n=1, cutoff=0.75)
    if match and match[0] != senderDomain:
        status = "suspicious"
        matched = match[0]
        message = f"Suspicious Domain: {senderDomain} (Similar to {matched})"
        print(message)
        return {"status": status, "matched": matched, "message": message}

    elif senderDomain not in safeDomains:
        status = "unknown"
        matched = None
        message = f"Unknown Domain: {senderDomain} not in whitelist"
        print(message)
        return {"status": status, "matched": matched, "message": message}

    else:
        status = "trusted"
        matched = senderDomain
        message = "Domain is trusted"
        return {"status": status, "matched": matched, "message": message}

trustableEmailDomains = loadWhitelist("trustable_email_domains.txt")


#code test below
""" 
if __name__ == "__main__":
    while True:
        email = input("Enter email to test or /q to quit: ").strip()
        if email.lower() == "/q":
            break
        score = editDistanceCheck(email, trustableEmailDomains)
        print(f"Sender: {email}, Test Score: {score}\n") 
"""