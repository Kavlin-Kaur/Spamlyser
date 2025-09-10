import re
from collections import Counter

def extract_links(text):
    # Regex for URLs (http, https, www)
    url_pattern = r'(https?://[^\s]+|www\.[^\s]+)'
    return re.findall(url_pattern, text)

def get_domain(url):
    # Extract domain from URL
    match = re.search(r'https?://([^/]+)', url)
    if match:
        return match.group(1)
    match = re.search(r'www\.([^/]+)', url)
    if match:
        return match.group(1)
    return None

def analyze_messages(messages):
    link_stats = []
    all_domains = []
    for msg in messages:
        links = extract_links(msg)
        is_suspicious = bool(links)
        domains = [get_domain(link) for link in links if get_domain(link)]
        all_domains.extend(domains)
        link_stats.append({
            'message': msg,
            'links': links,
            'domains': domains,
            'suspicious': is_suspicious
        })
    # Summary analytics
    total = len(messages)
    with_links = sum(1 for stat in link_stats if stat['suspicious'])
    percent_with_links = (with_links / total) * 100 if total else 0
    domain_counts = Counter(all_domains).most_common()
    return link_stats, percent_with_links, domain_counts

# Example usage and test
if __name__ == "__main__":
    messages = [
        "WINNER! Click http://scam.com to claim your prize.",
        "Hi Mom, just letting you know I'm home safe.",
        "Urgent: Your bank account has been compromised. Verify at https://bit.ly/malicious",
        "Check out www.example.com for more info.",
        "No links here, just a normal message."
    ]
    stats, percent, domains = analyze_messages(messages)
    for stat in stats:
        print(f"Message: {stat['message']}")
        print(f"Links: {stat['links']}")
        print(f"Suspicious: {stat['suspicious']}")
        print(f"Domains: {stat['domains']}")
        print("-" * 40)
    print(f"Percentage of messages with links: {percent:.2f}%")
    print("Most frequent domains:", domains)