import whois
import socket
import requests
import exifread
from duckduckgo_search import DDGS
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re

# === Utility Functions ===
def print_header(title):
    print(f"\n{'=' * 60}\n[+] {title}\n{'=' * 60}")

def get_domain_info(domain):
    print_header(f"WHOIS Info for {domain}")
    try:
        data = whois.whois(domain)
        for key, value in data.items():
            print(f"{key}: {value}")
    except Exception as e:
        print(f"[!] WHOIS lookup failed: {e}")

def get_ip_info(domain):
    print_header(f"IP Geolocation for {domain}")
    try:
        ip = socket.gethostbyname(domain)
        print(f"IP Address: {ip}")
        # CIDR approximation
        cidr = ".".join(ip.split(".")[:2]) + ".0.0/16"
        print(f"CIDR: {cidr}")
        print(f"Org: Use Shodan/Censys for real org info (not public DNS)")
    except Exception as e:
        print(f"[!] IP lookup failed: {e}")

def scrape_website(url):
    print_header(f"Scraping Emails and Social Links from {url}")
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        res = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(res.text, 'html.parser')

        # Extract emails
        emails = set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", res.text))
        if emails:
            print("\nFound Emails:")
            for email in emails:
                print(f" - {email}")
        else:
            print("No emails found.")

        # Extract social links
        social_links = []
        for link in soup.find_all("a", href=True):
            href = link['href']
            if any(s in href for s in ['facebook', 'twitter', 'linkedin', 'instagram', 'github']):
                social_links.append(href)

        if social_links:
            print("\nFound Social Links:")
            for link in set(social_links):
                print(f" - {link}")
        else:
            print("No social links found.")
    except Exception as e:
        print(f"[!] Scraping failed: {e}")

def extract_image_metadata(image_url):
    print_header(f"Extracting Metadata from Image URL: {image_url}")
    try:
        res = requests.get(image_url, stream=True)
        if res.status_code == 200:
            with open("temp.jpg", "wb") as f:
                f.write(res.content)
            with open("temp.jpg", "rb") as img_file:
                tags = exifread.process_file(img_file)
                if tags:
                    for tag in tags.keys():
                        print(f"{tag}: {tags[tag]}")
                else:
                    print("No metadata found.")
        else:
            print("[!] Failed to download image.")
    except Exception as e:
        print(f"[!] Metadata extraction failed: {e}")

def run_dorking(domain):
    print_header(f"Dorking Results for {domain}")
    dorks = [
        f"site:{domain} inurl:login",
        f"site:{domain} filetype:pdf",
        f"site:{domain} intitle:index.of",
        f"site:{domain} confidential",
        f"site:{domain} intext:password"
    ]

    try:
        with DDGS() as ddgs:
            for dork in dorks:
                print(f"\n🔍 Dork: {dork}")
                results = ddgs.text(dork, max_results=3)
                for r in results:
                    print(f" - {r['title']}: {r['href']}")
    except Exception as e:
        print(f"[!] Dorking failed: {e}")

# === Main Program ===
if __name__ == "__main__":
    domain_input = input("Enter domain (e.g. example.com): ").strip()
    if not domain_input:
        print("Please enter a valid domain.")
        exit()

    parsed = urlparse(domain_input)
    domain = parsed.netloc or domain_input
    full_url = f"http://{domain}"

    get_domain_info(domain)
    get_ip_info(domain)
    scrape_website(full_url)
    run_dorking(domain)

    image_input = input("\nDo you want to extract metadata from an image URL? (y/n): ").strip().lower()
    if image_input == 'y':
        image_url = input("Enter image URL: ").strip()
        if image_url:
            extract_image_metadata(image_url)
