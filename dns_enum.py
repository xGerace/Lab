import dns.resolver

# Function to query and print DNS A records (IP Addresses)
def query_a_records(domain):
    try:
        a_records = dns.resolver.resolve(domain, 'A')
        for ipval in a_records:
            print('A Record:', ipval.to_text())
    except Exception as e:
        print(f"An error occurred while querying A records for {domain}: {e}")

# Function to query and print DNS NS records (Name Servers)
def query_ns_records(domain):
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for nameserver in ns_records:
            print('NS Record:', nameserver.to_text())
    except Exception as e:
        print(f"An error occurred while querying NS records for {domain}: {e}")

# Function to query and print DNS MX records (Mail Servers)
def query_mx_records(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        for mailserver in mx_records:
            print('MX Record:', mailserver.exchange.to_text(), 'Priority:', mailserver.preference)
    except Exception as e:
        print(f"An error occurred while querying MX records for {domain}: {e}")

# Main function to handle user input and perform the queries
def main():
    # Prompt the user for the domain
    target_domain = input("Please enter the domain you wish to query: ").strip()

    # Perform the queries
    print(f"\nDNS Enumeration for: {target_domain}\n")
    query_a_records(target_domain)
    query_ns_records(target_domain)
    query_mx_records(target_domain)

if __name__ == "__main__":
    main()