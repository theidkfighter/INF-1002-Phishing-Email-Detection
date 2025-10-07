#importing libraries here
import re
from urllib.parse import urlparse, urljoin
import tldextract 

# email_body = "asdiamsodsapcpo ajd jaspod jaspo www.facebook.com asijdia https://172.169.152.10:80 sjd ojop jsapojdasjod jasodj posaj posajpodjapos <a href='https://www.google.com'>http://yahoo.com</a> jdpoajs poajspojop ajpojsap ojpaosj doj ansdnaslkdnaklsdn https://www.yahoo.com apisojdpioas jdpoasjdpoasj dpojasp odjapos djpoasj dpoasjd poasjd poajspdo japosdjaspo https://bit.ly/123710237 ajslkdklasndkl; asndpi asndi ans idnasios dnioasn ipdoansio dnaiosd nioans dionaoisd naiosdn iaons diojaniosd nian sdi https://www.paypal.asd.verify.asdf.payme.addaccount.yes.com"
# email_body = 'asdonaioscnioacnipascniasncisan ciopansiocnaiso cnioan cios ancoiasn cioanioa nsioc'


def susUrlDetect(email_body):
    result = {'riskMsg':[],"riskScore":0}
    riskScore = 0
    url_pattern = r'<a\s+(?:[^>]*?\s+)?href=(["\'])(.*?)\1.*?>(.*?)<\/a>|(https?:\/\/[^\s<>]+)' #the regex to find urls 

    found_urls = re.finditer(url_pattern, email_body, re.IGNORECASE) #extracting all urls from email using re library
    
    urlShort = ['bit.ly', 'goo.gl', 'tinyurl.com'] #exmaple list of shortened urls
    
    for match in found_urls:
        # Group 2: href from <a> tag, Group 3: anchor text from <a> tag, Group 4: raw URL
        #extracting urls from regex library data
        url=match.group(2) or match.group(4)
        anchorText = match.group(3)
        if not url:  # just incase the regex search failed and gave a empty value
            continue
        
        #Cleaning of url data
        parsed_url = urlparse(url) # sort the url to useful categories
        # e.g using urlparse
        # urlparse("http://docs.python.org:80/3/library/urllib.parse.html?highlight=params#url-parsing")
        # ParseResult(scheme='http', netloc='docs.python.org:80', path='/3/library/urllib.parse.html', params='',query='highlight=params', fragment='url-parsing')
        
        netloc = parsed_url.netloc # this will get the domain itself
        
        extracted_domain = tldextract.extract(netloc) 
        # this is too clean the netloc from the domain if it is an ip address it will split the port accessed 
        # e.g tldextract.extract('http://forums.news.cnn.com/')
        # ExtractResult(subdomain='forums.news', domain='cnn', suffix='com', is_private=False)
        
        
        #IP Detection
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' # regex to find ip address in url that was found in the email
        if re.match(ip_pattern, extracted_domain.domain):
            result['riskMsg'].append(f'SUSPICIOUS URL: Uses IP address directly: {url}')
            riskScore += 1
        
        #Checking if there is <a> tag. Comparing anchor text and href url if they are pointing to the same domains
        if anchorText:
            if 'http' or 'https' in anchorText:
                anchorDomain = tldextract.extract(anchorText).domain
                if anchorDomain != extracted_domain and anchorDomain != '':
                    riskScore += 1
                    result['riskMsg'].append(f'SUSPICIOUS URL: Anchor text {anchorText} and the {url} extracted from the href tag is pointing to different domains')
        
        
        # Checking if it uses url shortener
        if netloc in urlShort:
            riskScore += 1
            result['riskMsg'].append(f'SUSPICIOUS URL: Uses url shortener: {url}')
            
        # Check if there is alot of subdomains
        if len(extracted_domain.subdomain.split('.')) > 3:
            riskScore += 1
            result['riskMsg'].append(f'SUSPICIOUS URL: Excessive subdomains likely meant to deceive: {url}')
        result['riskScore'] = riskScore
    return result
