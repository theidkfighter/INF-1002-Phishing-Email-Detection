import difflib

def loadWhitelist(txtPath):
    # load whitelist dataset
    try:
        with open(txtPath, "r") as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        print("Dataset Missing")
        return set()


def editDistanceCheck(senderEmail, safeDomains):
    senderDomain = senderEmail.split("@")[-1].lower() if "@" in senderEmail else ""
    riskScore = 0

    # suspicious represents a domain that is not in the trusted list but is similar to a trusted domain
    match = difflib.get_close_matches(senderDomain, safeDomains, n=1, cutoff=0.75)
    if match and match[0] != senderDomain:
        status = "suspicious"
        matched = match[0]
        riskScore += 1
        message = f"Suspicious Domain: {senderDomain} (Similar to {matched})"
        return {"status": status, "matched": matched, "message": message, "riskScore":riskScore}

    # unknown represents a domain that is not in the trusted list and has no similar matches
    elif senderDomain not in safeDomains:
        status = "unknown"
        matched = None
        message = f"Unknown Domain: {senderDomain} not in whitelist"
        riskScore += 1

        return {"status": status, "matched": matched, "message": message,"riskScore":riskScore}

    # trusted represents a domain that is in the trusted list
    else:
        status = "trusted"
        matched = senderDomain
        message = "Domain is trusted"
        return {"status": status, "matched": matched, "message": message,"riskScore":0}

trustableEmailDomains = loadWhitelist("trustable_email_domains.txt")