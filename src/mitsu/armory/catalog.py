"""Curated offensive assessment catalog and allowlisted install sources."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CategorySpec:
    id: str
    name: str
    description: str


@dataclass(frozen=True)
class InstallMethod:
    """A known upstream ecosystem install path; no command comes from user input."""

    kind: str
    package: str
    executable: str
    source: str = ""
    prerequisite_packages: dict[str, tuple[str, ...]] | None = None
    supported_managers: tuple[str, ...] = ()
    requirements_file: str = ""

    @property
    def id(self) -> str:
        return f"{self.kind}:{self.package}"


@dataclass(frozen=True)
class ToolSpec:
    id: str
    name: str
    category_id: str
    description: str
    packages: dict[str, str]
    executables: tuple[str, ...]
    install_methods: tuple[InstallMethod, ...] = ()


CATEGORIES = (
    CategorySpec("osint-recon", "OSINT / Recon", "Discover public assets and map an explicitly authorized target surface."),
    CategorySpec("network-mapping", "Network Mapping", "Identify hosts and services inside an approved network scope."),
    CategorySpec("web-assessment", "Web Application Assessment", "Assess web applications and content-management systems."),
    CategorySpec("api-assessment", "API Security Assessment", "Assess REST, GraphQL, and token-based APIs with owner approval."),
    CategorySpec("database-assessment", "Database Assessment", "Review database exposure and validate controls in an authorized environment."),
    CategorySpec("vulnerability", "Vulnerability Assessment", "Identify known exposures and review security posture."),
    CategorySpec("password-auditing", "Password Auditing", "Audit approved test hashes and authentication controls."),
    CategorySpec("exploitation", "Exploitation Frameworks", "Validate vulnerabilities in a lab or explicitly authorized engagement."),
    CategorySpec("active-directory", "Active Directory", "Assess Windows domains and identity paths with client authorization."),
    CategorySpec("post-exploitation", "Post-Exploitation & Pivoting", "Assess established lab access, privilege boundaries, and routes."),
    CategorySpec("traffic-assessment", "Traffic Analysis & Spoofing", "Inspect or manipulate traffic only on networks you own or are approved to test."),
    CategorySpec("wireless", "Wireless Security", "Assess wireless networks and devices you own or are authorized to test."),
    CategorySpec("hardware-radio", "Hardware & Radio", "Assess owned or explicitly authorized Bluetooth, SDR, and radio equipment."),
    CategorySpec("social-engineering", "Social Engineering Simulations", "Run approved awareness exercises with a controlled audience and infrastructure."),
    CategorySpec("cloud-container", "Cloud & Container Assessment", "Review cloud, image, and Kubernetes configurations in scope."),
    CategorySpec("mobile", "Mobile Application Assessment", "Inspect Android applications and mobile test environments."),
    CategorySpec("forensics-reversing", "Forensics / Reverse Engineering", "Inspect binaries, firmware, applications, and evidence files."),
)


def _method(
    kind: str,
    package: str,
    executable: str,
    source: str = "",
    prerequisite_packages: dict[str, tuple[str, ...]] | None = None,
    supported_managers: tuple[str, ...] = (),
    requirements_file: str = "",
) -> InstallMethod:
    requirements = {
        "go": _GO_PREREQUISITES,
        "cargo": _CARGO_PREREQUISITES,
        "gem": _GEM_PREREQUISITES,
        "pipx": _PIPX_PREREQUISITES,
        "git": _GIT_PREREQUISITES,
        "python-source": _PYTHON_SOURCE_PREREQUISITES,
        "python-project": _PYTHON_SOURCE_PREREQUISITES,
        "official-script": _CURL_PREREQUISITES,
    }
    selected_requirements = prerequisite_packages or requirements.get(kind)
    return InstallMethod(
        kind,
        package,
        executable,
        source,
        selected_requirements,
        supported_managers,
        requirements_file,
    )


_GO_PREREQUISITES = {
    "apt-get": ("golang-go",), "pacman": ("go",), "dnf": ("golang",),
    "yum": ("golang",), "zypper": ("go",), "apk": ("go",),
}
_CARGO_PREREQUISITES = {
    "apt-get": ("cargo",), "pacman": ("cargo",), "dnf": ("cargo",),
    "yum": ("cargo",), "zypper": ("cargo",), "apk": ("cargo",),
}
_GEM_PREREQUISITES = {
    "apt-get": ("ruby", "ruby-dev", "build-essential"),
    "pacman": ("ruby", "base-devel"),
    "dnf": ("ruby", "ruby-devel", "gcc", "make"),
    "yum": ("ruby", "ruby-devel", "gcc", "make"),
    "zypper": ("ruby", "ruby-devel", "gcc", "make"),
    "apk": ("ruby", "ruby-dev", "build-base"),
}
_PIPX_PREREQUISITES = {
    "apt-get": ("pipx",), "pacman": ("python-pipx",), "dnf": ("pipx",),
    "yum": ("pipx",), "zypper": ("python3-pipx",), "apk": ("py3-pipx",),
}
_GIT_PREREQUISITES = {
    "apt-get": ("git",), "pacman": ("git",), "dnf": ("git",),
    "yum": ("git",), "zypper": ("git",), "apk": ("git",),
}
_PYTHON_SOURCE_PREREQUISITES = {
    "apt-get": ("git", "python3", "python3-venv", "python3-pip"),
    "pacman": ("git", "python", "python-pip"),
    "dnf": ("git", "python3", "python3-pip"),
    "yum": ("git", "python3", "python3-pip"),
    "zypper": ("git", "python3", "python3-pip"),
    "apk": ("git", "python3", "py3-pip"),
}
_ENUM4LINUX_PREREQUISITES = {
    "apt-get": _PYTHON_SOURCE_PREREQUISITES["apt-get"] + ("smbclient",),
    "pacman": _PYTHON_SOURCE_PREREQUISITES["pacman"] + ("smbclient",),
    "dnf": _PYTHON_SOURCE_PREREQUISITES["dnf"] + ("samba-client",),
    "yum": _PYTHON_SOURCE_PREREQUISITES["yum"] + ("samba-client",),
    "zypper": _PYTHON_SOURCE_PREREQUISITES["zypper"] + ("samba-client",),
    "apk": _PYTHON_SOURCE_PREREQUISITES["apk"] + ("samba-client",),
}
_CURL_PREREQUISITES = {
    "apt-get": ("curl", "bash"), "pacman": ("curl", "bash"), "dnf": ("curl", "bash"),
    "yum": ("curl", "bash"), "zypper": ("curl", "bash"), "apk": ("curl", "bash"),
}


def _tool(
    tool_id: str,
    name: str,
    category_id: str,
    description: str,
    apt_package: str,
    executables: tuple[str, ...],
    *,
    pacman_package: str | None = None,
    other_packages: dict[str, str] | None = None,
    install_methods: tuple[InstallMethod, ...] = (),
) -> ToolSpec:
    packages = {
        manager_id: apt_package
        for manager_id in ("apt-get", "pacman", "dnf", "yum", "zypper", "apk")
    }
    packages["pacman"] = pacman_package or apt_package
    packages.update(other_packages or {})
    return ToolSpec(tool_id, name, category_id, description, packages, executables, install_methods)


# Package names are the native Kali/Debian or Arch/BlackArch names where
# available. Ecosystem methods provide user-scoped alternatives on other hosts.
TOOLS = (
    # OSINT and reconnaissance
    _tool("amass", "OWASP Amass", "osint-recon", "Map an authorized attack surface and discover related assets.", "amass", ("amass",)),
    _tool("subfinder", "Subfinder", "osint-recon", "Passive subdomain discovery using configured public sources.", "subfinder", ("subfinder",), install_methods=(_method("go", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder", "subfinder"),)),
    _tool("assetfinder", "assetfinder", "osint-recon", "Find domains and subdomains associated with an approved domain.", "assetfinder", ("assetfinder",), install_methods=(_method("go", "github.com/tomnomnom/assetfinder", "assetfinder"),)),
    _tool("theharvester", "theHarvester", "osint-recon", "Collect public-facing names, hosts, and metadata from supported sources.", "theharvester", ("theHarvester", "theharvester"), install_methods=(_method("pipx", "theHarvester", "theHarvester"),)),
    _tool("recon-ng", "Recon-ng", "osint-recon", "Modular framework for authorized open-source intelligence work.", "recon-ng", ("recon-ng",), install_methods=(_method("python-source", "recon-ng", "recon-ng", "https://github.com/lanmaster53/recon-ng.git", requirements_file="REQUIREMENTS"),)),
    _tool("spiderfoot", "SpiderFoot", "osint-recon", "Correlate public-source intelligence for an approved domain or organization.", "spiderfoot", ("sf", "spiderfoot")),
    _tool("sherlock", "Sherlock", "osint-recon", "Check public sites for a supplied username; respect site terms and consent.", "sherlock", ("sherlock",), install_methods=(_method("pipx", "sherlock-project", "sherlock", "sherlock-project"),)),
    _tool("maigret", "Maigret", "osint-recon", "Search public sites for a supplied username using its supported site list.", "maigret", ("maigret",), install_methods=(_method("pipx", "maigret", "maigret"),)),
    _tool("dnsrecon", "DNSRecon", "osint-recon", "Enumerate DNS records and configuration for an authorized domain.", "dnsrecon", ("dnsrecon",), install_methods=(_method("pipx", "dnsrecon", "dnsrecon", "git+https://github.com/darkoperator/dnsrecon.git"),)),
    _tool("dnsenum", "DNSenum", "osint-recon", "Review DNS records and names for an explicitly authorized domain.", "dnsenum", ("dnsenum",)),
    _tool("fierce", "Fierce", "osint-recon", "DNS reconnaissance for domains you are authorized to assess.", "fierce", ("fierce",), install_methods=(_method("pipx", "fierce", "fierce"),)),
    _tool("dmitry", "DMitry", "osint-recon", "Gather public host, domain, and contact information for an approved target.", "dmitry", ("dmitry",)),
    _tool("whois", "WHOIS", "osint-recon", "Query public registration records for domains and IP allocations.", "whois", ("whois",)),
    _tool("gau", "gau", "osint-recon", "Collect known URLs from public web archives for an approved domain.", "gau", ("gau",), install_methods=(_method("go", "github.com/lc/gau/v2/cmd/gau", "gau"),)),
    _tool("waybackurls", "waybackurls", "osint-recon", "Retrieve URLs known to the Wayback Machine for an approved domain.", "waybackurls", ("waybackurls",), install_methods=(_method("go", "github.com/tomnomnom/waybackurls", "waybackurls"),)),
    _tool("katana", "Katana", "osint-recon", "Crawl an authorized web application and collect discovered endpoints.", "katana", ("katana",), install_methods=(_method("go", "github.com/projectdiscovery/katana/cmd/katana", "katana"),)),
    _tool("cloud-enum", "CloudEnum", "osint-recon", "Discover publicly exposed cloud-storage names for an approved organization.", "cloud-enum", ("cloud_enum.py", "cloud_enum"), install_methods=(_method("python-source", "cloud-enum", "cloud_enum.py", "https://github.com/initstring/cloud_enum.git", requirements_file="requirements.txt"),)),
    _tool("shodan-cli", "Shodan CLI", "osint-recon", "Query Shodan for assets in scope; requires a Shodan API key.", "shodan", ("shodan",), install_methods=(_method("pipx", "shodan", "shodan"),)),
    _tool("censys-cli", "Censys CLI", "osint-recon", "Query Censys for assets in scope; requires configured Censys credentials.", "censys", ("censys",), install_methods=(_method("pipx", "censys", "censys"),)),
    _tool("asnmap", "ASNMap", "osint-recon", "Map an approved organization or domain to its public ASN and network ranges.", "asnmap", ("asnmap",), install_methods=(_method("go", "github.com/projectdiscovery/asnmap/cmd/asnmap", "asnmap"),)),
    _tool("urlfinder", "URLFinder", "osint-recon", "Find URLs associated with explicitly scoped domains using public sources.", "urlfinder", ("urlfinder",), install_methods=(_method("go", "github.com/projectdiscovery/urlfinder/cmd/urlfinder", "urlfinder"),)),
    _tool("tlsx", "tlsx", "osint-recon", "Collect TLS certificate and service metadata for assets confirmed in scope.", "tlsx", ("tlsx",), install_methods=(_method("go", "github.com/projectdiscovery/tlsx/cmd/tlsx", "tlsx"),)),

    # Network mapping
    _tool("nmap", "Nmap", "network-mapping", "Host discovery, port mapping, and service identification in scope.", "nmap", ("nmap",), other_packages={"dnf": "nmap", "yum": "nmap", "zypper": "nmap", "apk": "nmap"}),
    _tool("masscan", "Masscan", "network-mapping", "High-speed port scanner; restrict it to an explicitly approved range.", "masscan", ("masscan",)),
    _tool("zmap", "ZMap", "network-mapping", "Internet-scale research scanner; use only on ranges with written authorization.", "zmap", ("zmap",)),
    _tool("rustscan", "RustScan", "network-mapping", "Fast port discovery with optional Nmap handoff.", "rustscan", ("rustscan",), install_methods=(_method("cargo", "rustscan", "rustscan"),)),
    _tool("arp-scan", "arp-scan", "network-mapping", "Discover systems on a directly connected network you administer.", "arp-scan", ("arp-scan",)),
    _tool("netdiscover", "Netdiscover", "network-mapping", "Discover hosts on a local network segment during an approved assessment.", "netdiscover", ("netdiscover",)),
    _tool("fping", "fping", "network-mapping", "Check host reachability across a controlled assessment scope.", "fping", ("fping",)),
    _tool("hping3", "hping3", "network-mapping", "Craft diagnostic packets for controlled network testing.", "hping3", ("hping3",)),
    _tool("naabu", "Naabu", "network-mapping", "Port discovery for domains and IP ranges explicitly in scope.", "naabu", ("naabu",), install_methods=(_method("go", "github.com/projectdiscovery/naabu/v2/cmd/naabu", "naabu"),)),
    _tool("dnsx", "dnsx", "network-mapping", "Resolve and inspect DNS records for authorized host lists.", "dnsx", ("dnsx",), install_methods=(_method("go", "github.com/projectdiscovery/dnsx/cmd/dnsx", "dnsx"),)),
    _tool("httpx", "httpx (ProjectDiscovery)", "network-mapping", "Probe HTTP services in an approved asset list.", "httpx-toolkit", ("httpx",), install_methods=(_method("go", "github.com/projectdiscovery/httpx/cmd/httpx", "httpx"),)),
    _tool("uncover", "Uncover", "network-mapping", "Query supported public search engines for authorized asset discovery.", "uncover", ("uncover",), install_methods=(_method("go", "github.com/projectdiscovery/uncover/cmd/uncover", "uncover"),)),
    _tool("autorecon", "AutoRecon", "network-mapping", "Run a configurable network reconnaissance workflow against explicitly scoped hosts.", "autorecon", ("autorecon",), install_methods=(_method("pipx", "autorecon", "autorecon", "git+https://github.com/Tib3rius/AutoRecon.git"),)),
    _tool("nbtscan", "NBTScan", "network-mapping", "Enumerate NetBIOS names on an authorized local network.", "nbtscan", ("nbtscan",)),
    _tool("enum4linux", "enum4linux", "network-mapping", "Enumerate SMB and Windows hosts using authorized lab accounts.", "enum4linux", ("enum4linux",)),
    _tool("smbmap", "SMBMap", "network-mapping", "Review SMB shares and permissions on systems in scope.", "smbmap", ("smbmap",), install_methods=(_method("pipx", "smbmap", "smbmap"),)),
    _tool("rpcclient", "rpcclient", "network-mapping", "Inspect SMB/RPC services on authorized Windows systems.", "smbclient", ("rpcclient",)),
    _tool("snmpwalk", "Net-SNMP Walk", "network-mapping", "Query SNMP data from managed devices with explicit authorization.", "snmp", ("snmpwalk",)),
    _tool("traceroute", "Traceroute", "network-mapping", "Map network paths to hosts within a controlled assessment scope.", "traceroute", ("traceroute", "tracepath")),
    _tool("netcat", "Netcat", "network-mapping", "Make controlled TCP and UDP connectivity checks against approved systems.", "netcat-openbsd", ("nc", "netcat"), pacman_package="openbsd-netcat", other_packages={"dnf": "nmap-ncat", "yum": "nmap-ncat", "zypper": "netcat-openbsd", "apk": "netcat-openbsd"}),
    _tool("socat", "socat", "network-mapping", "Create controlled TCP, UDP, and Unix-socket connections in a lab or approved scope.", "socat", ("socat",)),

    # Web application assessment
    _tool("burpsuite", "Burp Suite Community", "web-assessment", "Intercepting proxy for manual testing of authorized web applications.", "burpsuite", ("burpsuite",)),
    _tool("zaproxy", "OWASP ZAP", "web-assessment", "Web testing proxy and scanner for applications you may assess.", "zaproxy", ("zaproxy",)),
    _tool("wpscan", "WPScan", "web-assessment", "Assess WordPress installations with owner approval; API data may require a token.", "wpscan", ("wpscan",), install_methods=(_method("gem", "wpscan", "wpscan"),)),
    _tool("sqlmap", "sqlmap", "web-assessment", "Test SQL injection behavior on authorized applications and test data.", "sqlmap", ("sqlmap",), install_methods=(_method("git", "sqlmap", "sqlmap.py", "https://github.com/sqlmapproject/sqlmap.git"),)),
    _tool("nikto", "Nikto", "web-assessment", "Review web-server configuration and known exposures on approved hosts.", "nikto", ("nikto", "nikto.pl"), install_methods=(_method("git", "nikto", "nikto.pl", "https://github.com/sullo/nikto.git"),)),
    _tool("gobuster", "Gobuster", "web-assessment", "Discover content and virtual hosts on approved web targets.", "gobuster", ("gobuster",), install_methods=(_method("go", "github.com/OJ/gobuster/v3", "gobuster"),)),
    _tool("paramspider", "ParamSpider", "web-assessment", "Collect archived URL parameters for an approved domain.", "paramspider", ("paramspider",), install_methods=(_method("python-source", "paramspider", "paramspider", "https://github.com/devanshbatham/ParamSpider.git", requirements_file="requirements.txt"),)),
    _tool("hakrawler", "hakrawler", "web-assessment", "Crawl an explicitly authorized application and list discovered endpoints.", "hakrawler", ("hakrawler",), install_methods=(_method("go", "github.com/hakluke/hakrawler", "hakrawler"),)),
    _tool("gospider", "GoSpider", "web-assessment", "Crawl approved web assets and discover linked URLs.", "gospider", ("gospider",), install_methods=(_method("go", "github.com/jaeles-project/gospider", "gospider"),)),
    _tool("jaeles", "Jaeles", "web-assessment", "Run curated web checks against applications confirmed in scope.", "jaeles", ("jaeles",), install_methods=(_method("go", "github.com/jaeles-project/jaeles", "jaeles"),)),
    _tool("x8", "x8", "web-assessment", "Discover hidden HTTP parameters on a controlled test application.", "x8", ("x8",), install_methods=(_method("cargo", "x8", "x8"),)),
    _tool("ffuf", "ffuf", "web-assessment", "Fuzz controlled web applications using an approved test wordlist.", "ffuf", ("ffuf",), install_methods=(_method("go", "github.com/ffuf/ffuf/v2", "ffuf"),)),
    _tool("feroxbuster", "feroxbuster", "web-assessment", "Content discovery for explicitly authorized web servers.", "feroxbuster", ("feroxbuster",), install_methods=(_method("cargo", "feroxbuster", "feroxbuster"),)),
    _tool("dirsearch", "dirsearch", "web-assessment", "Discover web paths on applications you are authorized to test.", "dirsearch", ("dirsearch",), install_methods=(_method("pipx", "dirsearch", "dirsearch"),)),
    _tool("dirb", "DIRB", "web-assessment", "Classic web content discovery for controlled targets.", "dirb", ("dirb",)),
    _tool("whatweb", "WhatWeb", "web-assessment", "Identify technologies exposed by an in-scope website.", "whatweb", ("whatweb",)),
    _tool("wafw00f", "WAFW00F", "web-assessment", "Identify web application firewalls on authorized targets.", "wafw00f", ("wafw00f",), install_methods=(_method("pipx", "wafw00f", "wafw00f"),)),
    _tool("arjun", "Arjun", "web-assessment", "Discover HTTP parameters on an approved application.", "arjun", ("arjun",), install_methods=(_method("pipx", "arjun", "arjun"),)),
    _tool("dalfox", "Dalfox", "web-assessment", "Validate suspected XSS behavior in an authorized test environment.", "dalfox", ("dalfox",), install_methods=(_method("go", "github.com/hahwul/dalfox/v2", "dalfox"),)),
    _tool("commix", "Commix", "web-assessment", "Test command-injection exposure on explicitly authorized applications.", "commix", ("commix",), install_methods=(_method("git", "commix", "commix.py", "https://github.com/commixproject/commix.git"),)),

    # API security assessment
    _tool("jwt-tool", "JWT Tool", "api-assessment", "Review JWT validation and token handling on an approved application.", "jwt-tool", ("jwt_tool.py",), install_methods=(_method("python-source", "jwt-tool", "jwt_tool.py", "https://github.com/ticarpi/jwt_tool.git", requirements_file="requirements.txt"),)),
    _tool("xsstrike", "XSStrike", "web-assessment", "Validate suspected cross-site scripting behavior on an authorized test application.", "xsstrike", ("xsstrike.py",), install_methods=(_method("python-source", "xsstrike", "xsstrike.py", "https://github.com/s0md3v/XSStrike.git", requirements_file="requirements.txt"),)),
    _tool("graphqlmap", "GraphQLmap", "api-assessment", "Inspect and test GraphQL endpoints that you own or are authorized to assess.", "graphqlmap", ("graphqlmap", "graphqlmap.py"), install_methods=(_method("python-project", "graphqlmap", "graphqlmap", "https://github.com/swisskyrepo/GraphQLmap.git", requirements_file="requirements.txt"),)),
    _tool("grpcurl", "grpcurl", "api-assessment", "Inspect gRPC services and schemas in an approved test environment.", "grpcurl", ("grpcurl",), install_methods=(_method("go", "github.com/fullstorydev/grpcurl/cmd/grpcurl", "grpcurl"),)),
    _tool("schemathesis", "Schemathesis", "api-assessment", "Generate API conformance tests from an approved OpenAPI or GraphQL schema.", "schemathesis", ("schemathesis",), install_methods=(_method("pipx", "schemathesis", "schemathesis"),)),

    # Database assessment
    _tool("nosqlmap", "NoSQLMap", "database-assessment", "Assess NoSQL database configurations in an isolated, authorized test environment.", "nosqlmap", ("nosqlmap",), install_methods=(_method("python-project", "nosqlmap", "nosqlmap.py", "https://github.com/codingo/NoSQLMap.git"),)),
    _tool("sqlninja", "sqlninja", "database-assessment", "Validate SQL Server injection findings in a lab or explicitly approved application.", "sqlninja", ("sqlninja",)),

    # Vulnerability assessment
    _tool("nuclei", "Nuclei", "vulnerability", "Run selected templates only against assets confirmed in scope.", "nuclei", ("nuclei",), install_methods=(_method("go", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei", "nuclei"),)),
    _tool("testssl", "testssl.sh", "vulnerability", "Review TLS configuration on systems you administer or are authorized to assess.", "testssl.sh", ("testssl",), pacman_package="testssl"),
    _tool("sslscan", "sslscan", "vulnerability", "Inspect TLS protocol and cipher support on an approved endpoint.", "sslscan", ("sslscan",)),
    _tool("sslyze", "SSLyze", "vulnerability", "Audit TLS configuration for approved services.", "sslyze", ("sslyze",), install_methods=(_method("pipx", "sslyze", "sslyze"),)),
    _tool("trivy", "Trivy", "vulnerability", "Scan local images, repositories, and dependencies for known exposures.", "trivy", ("trivy",), install_methods=(_method("official-script", "trivy", "trivy", "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh"),)),
    _tool("checkov", "Checkov", "vulnerability", "Review infrastructure-as-code and cloud configuration for risky settings.", "checkov", ("checkov",), install_methods=(_method("pipx", "checkov", "checkov"),)),
    _tool("grype", "Grype", "vulnerability", "Identify known vulnerabilities in local container images and filesystems.", "grype", ("grype",), install_methods=(_method("official-script", "grype", "grype", "https://raw.githubusercontent.com/anchore/grype/main/install.sh"),)),

    # Password auditing
    _tool("john", "John the Ripper", "password-auditing", "Audit approved test hashes and password policy samples.", "john", ("john", "john-the-ripper")),
    _tool("hashcat", "Hashcat", "password-auditing", "Recover or audit passwords from approved test hashes.", "hashcat", ("hashcat",)),
    _tool("hydra", "THC Hydra", "password-auditing", "Assess authentication controls only on explicitly authorized services.", "hydra", ("hydra",)),
    _tool("medusa", "Medusa", "password-auditing", "Test login controls against approved lab services and test accounts.", "medusa", ("medusa",)),
    _tool("ncrack", "Ncrack", "password-auditing", "Audit network authentication on services in written scope.", "ncrack", ("ncrack",)),
    _tool("hashid", "HashID", "password-auditing", "Identify likely formats for supplied password hashes.", "hashid", ("hashid",)),
    _tool("crunch", "Crunch", "password-auditing", "Generate bounded test wordlists for controlled password audits.", "crunch", ("crunch",)),
    _tool("patator", "Patator", "password-auditing", "Audit authentication controls using approved test accounts and rate limits.", "patator", ("patator",), install_methods=(_method("python-source", "patator", "patator.py", "https://github.com/lanjelot/patator.git", requirements_file="requirements.txt"),)),
    _tool("hash-identifier", "Hash Identifier", "password-auditing", "Identify likely formats for supplied test hashes.", "hash-identifier", ("hash-identifier",), install_methods=(_method("git", "hash-identifier", "hash-id.py", "https://github.com/psypanda/hashID.git"),)),
    _tool("ophcrack", "Ophcrack", "password-auditing", "Audit Windows password hashes supplied for an authorized assessment.", "ophcrack", ("ophcrack",)),
    _tool("stegseek", "Stegseek", "password-auditing", "Audit steganography passwords against owned test files.", "stegseek", ("stegseek",)),
    _tool("crowbar", "Crowbar", "password-auditing", "Audit authentication controls with approved test accounts and strict rate limits.", "crowbar", ("crowbar",)),
    _tool("fcrackzip", "fcrackzip", "password-auditing", "Audit password strength on archive files provided for testing.", "fcrackzip", ("fcrackzip",)),
    _tool("cewl", "CeWL", "password-auditing", "Build a bounded test wordlist from content you own or are authorized to assess.", "cewl", ("cewl",)),

    # Exploitation frameworks
    _tool("metasploit", "Metasploit Framework", "exploitation", "Validate known vulnerabilities in an isolated lab or approved engagement.", "metasploit-framework", ("msfconsole",), pacman_package="metasploit", install_methods=(_method("official-script", "metasploit-framework", "msfconsole", "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfinstall", supported_managers=("apt-get",)),)),
    _tool("exploitdb", "Exploit-DB / SearchSploit", "exploitation", "Search local public vulnerability references; entries require independent validation.", "exploitdb", ("searchsploit",)),
    _tool("routersploit", "RouterSploit", "exploitation", "Validate known router and embedded-device issues in owned test environments.", "routersploit", ("rsf",), install_methods=(_method("pipx", "routersploit", "rsf"),)),

    # Active Directory and identity assessment
    _tool("netexec", "NetExec", "active-directory", "Assess Windows-domain services using approved test identities and scope.", "netexec", ("nxc", "NetExec"), install_methods=(_method("pipx", "netexec", "NetExec", "git+https://github.com/Pennyw0rth/NetExec"),)),
    _tool("impacket", "Impacket", "active-directory", "Protocol clients for authorized Windows-domain assessments and labs.", "python3-impacket", ("impacket-secretsdump", "impacket-psexec", "impacket-wmiexec"), pacman_package="python-impacket", install_methods=(_method("pipx", "impacket", "impacket-secretsdump"),)),
    _tool("bloodhound-python", "BloodHound.py", "active-directory", "Collect Active Directory relationship data using authorized domain access.", "bloodhound.py", ("bloodhound-python",)),
    _tool("certipy-ad", "Certipy", "active-directory", "Audit Active Directory Certificate Services configuration in an approved domain.", "certipy-ad", ("certipy",), install_methods=(_method("pipx", "certipy-ad", "certipy"),)),
    _tool("enum4linux-ng", "enum4linux-ng", "active-directory", "Enumerate SMB and Windows-domain information using approved accounts.", "enum4linux-ng", ("enum4linux-ng",), install_methods=(_method("python-source", "enum4linux-ng", "enum4linux-ng.py", "https://github.com/cddmp/enum4linux-ng.git", prerequisite_packages=_ENUM4LINUX_PREREQUISITES, requirements_file="requirements.txt"),)),
    _tool("kerbrute", "Kerbrute", "active-directory", "Validate Kerberos identity controls in a lab or explicitly approved domain.", "kerbrute", ("kerbrute",), install_methods=(_method("go", "github.com/ropnop/kerbrute", "kerbrute"),)),
    _tool("ldapdomaindump", "ldapdomaindump", "active-directory", "Document domain directory data using approved credentials.", "ldapdomaindump", ("ldapdomaindump",), install_methods=(_method("pipx", "ldapdomaindump", "ldapdomaindump"),)),
    _tool("adidnsdump", "ADIDNSDump", "active-directory", "Review Active Directory DNS records in an authorized domain.", "adidnsdump", ("adidnsdump",), install_methods=(_method("pipx", "adidnsdump", "adidnsdump"),)),
    _tool("bloodyad", "bloodyAD", "active-directory", "Review Active Directory permissions and controls in a client-approved domain.", "bloodyad", ("bloodyAD", "bloodyad"), install_methods=(_method("pipx", "bloodyAD", "bloodyAD"),)),
    _tool("coercer", "Coercer", "active-directory", "Validate Windows authentication coercion exposure in a controlled domain lab.", "coercer", ("coercer",), install_methods=(_method("pipx", "coercer", "coercer"),)),
    _tool("pypykatz", "pypykatz", "active-directory", "Analyze credential artifacts from authorized Windows memory and test data.", "pypykatz", ("pypykatz",), install_methods=(_method("pipx", "pypykatz", "pypykatz"),)),

    # Post-exploitation and pivoting
    _tool("evil-winrm", "Evil-WinRM", "post-exploitation", "Connect to Windows lab systems with credentials you are authorized to use.", "evil-winrm", ("evil-winrm",), install_methods=(_method("gem", "evil-winrm", "evil-winrm"),)),
    _tool("responder", "Responder", "post-exploitation", "Assess name-resolution exposure on isolated, authorized network segments.", "responder", ("Responder.py", "responder")),
    _tool("ligolo-ng", "Ligolo-ng", "post-exploitation", "Create a controlled pivot in a lab or approved network assessment.", "ligolo-ng", ("ligolo-ng",), install_methods=(_method("go", "github.com/nicocha30/ligolo-ng/cmd/proxy", "proxy"),)),
    _tool("chisel", "Chisel", "post-exploitation", "Set up a test tunnel between systems you control.", "chisel", ("chisel",), install_methods=(_method("go", "github.com/jpillora/chisel", "chisel"),)),
    _tool("proxychains", "ProxyChains-NG", "post-exploitation", "Route selected test utilities through a configured proxy.", "proxychains4", ("proxychains4", "proxychains")),
    _tool("sshuttle", "sshuttle", "post-exploitation", "Build an SSH-based lab route using authorized credentials.", "sshuttle", ("sshuttle",)),
    _tool("pspy", "pspy", "post-exploitation", "Observe process activity on systems where you have authorized access.", "pspy", ("pspy",), install_methods=(_method("go", "github.com/DominicBreuker/pspy", "pspy"),)),
    _tool("linpeas", "LinPEAS", "post-exploitation", "Review privilege boundaries on an authorized Linux test host.", "linpeas", ("linpeas.sh",), install_methods=(_method("git", "linpeas", "linpeas.sh", "https://github.com/peass-ng/PEASS-ng.git"),)),
    _tool("winpeas", "WinPEAS", "post-exploitation", "Review privilege boundaries on an authorized Windows test host.", "winpeas", ("winpeas.exe",), install_methods=(_method("git", "winpeas", "winpeas.exe", "https://github.com/peass-ng/PEASS-ng.git"),)),

    # Traffic analysis and spoofing
    _tool("tcpdump", "tcpdump", "traffic-assessment", "Capture packets only on interfaces and networks you are authorized to inspect.", "tcpdump", ("tcpdump",)),
    _tool("wireshark", "Wireshark", "traffic-assessment", "Inspect authorized packet captures and controlled test traffic.", "wireshark", ("wireshark",), pacman_package="wireshark-qt", other_packages={"dnf": "wireshark", "yum": "wireshark", "zypper": "wireshark", "apk": "wireshark"}),
    _tool("tshark", "TShark", "traffic-assessment", "Filter and inspect approved packet captures from the command line.", "tshark", ("tshark",), pacman_package="wireshark-cli", other_packages={"dnf": "wireshark-cli", "yum": "wireshark", "zypper": "wireshark", "apk": "wireshark"}),
    _tool("dsniff", "dsniff", "traffic-assessment", "Inspect controlled lab traffic and validate network trust boundaries.", "dsniff", ("dsniff", "arpspoof", "urlsnarf")),
    _tool("ettercap", "Ettercap", "traffic-assessment", "Test network segmentation and traffic protections on an isolated, approved network.", "ettercap-text-only", ("ettercap", "ettercap-text"), pacman_package="ettercap", other_packages={"dnf": "ettercap", "yum": "ettercap", "zypper": "ettercap", "apk": "ettercap"}),
    _tool("mitmproxy", "mitmproxy", "traffic-assessment", "Inspect application traffic in an owned test environment or approved assessment.", "mitmproxy", ("mitmproxy",), install_methods=(_method("pipx", "mitmproxy", "mitmproxy"),)),

    # Wireless security
    _tool("aircrack-ng", "Aircrack-ng", "wireless", "Audit wireless security on networks and equipment you own or may test.", "aircrack-ng", ("aircrack-ng",), other_packages={"dnf": "aircrack-ng", "zypper": "aircrack-ng"}),
    _tool("bettercap", "Bettercap", "wireless", "Assess networks and wireless devices in a controlled test environment.", "bettercap", ("bettercap",)),
    _tool("kismet", "Kismet", "wireless", "Monitor wireless activity on networks and devices you administer.", "kismet", ("kismet",)),
    _tool("wifite", "Wifite", "wireless", "Automate authorized wireless security checks against your own test network.", "wifite", ("wifite",)),
    _tool("hcxdumptool", "hcxdumptool", "wireless", "Capture wireless assessment data from an owned test network.", "hcxdumptool", ("hcxdumptool",)),
    _tool("hcxtools", "hcxtools", "wireless", "Process captures produced during an authorized wireless audit.", "hcxtools", ("hcxpcapngtool", "hcxhash2cap")),

    # Hardware and radio assessment
    _tool("bluez", "BlueZ", "hardware-radio", "Inspect Bluetooth devices that you own or are authorized to assess.", "bluez", ("bluetoothctl", "btmon")),
    _tool("hackrf", "HackRF Tools", "hardware-radio", "Assess radio-frequency systems using hardware you own or have permission to test.", "hackrf", ("hackrf_info", "hackrf_transfer")),
    _tool("rtl-sdr", "RTL-SDR Tools", "hardware-radio", "Inspect authorized radio test signals with compatible RTL-SDR hardware.", "rtl-sdr", ("rtl_test", "rtl_tcp")),
    _tool("gqrx", "Gqrx SDR", "hardware-radio", "Review radio signals in a controlled lab using supported SDR hardware.", "gqrx-sdr", ("gqrx",), pacman_package="gqrx", other_packages={"dnf": "gqrx", "yum": "gqrx", "zypper": "gqrx", "apk": "gqrx"}),
    _tool("ubertooth", "Ubertooth Tools", "hardware-radio", "Assess Bluetooth Low Energy behavior with owned Ubertooth hardware.", "ubertooth", ("ubertooth-util", "ubertooth-rx")),

    # Social engineering simulations
    _tool("setoolkit", "Social-Engineer Toolkit", "social-engineering", "Run approved social-engineering simulations with a controlled audience.", "set", ("setoolkit",), pacman_package="setoolkit"),
    _tool("gophish", "Gophish", "social-engineering", "Run consent-based phishing-awareness simulations for an approved organization.", "gophish", ("gophish",), install_methods=(_method("go", "github.com/gophish/gophish", "gophish"),)),

    # Cloud and container assessment
    _tool("prowler", "Prowler", "cloud-container", "Audit cloud account configuration with explicit account authorization.", "prowler", ("prowler",), install_methods=(_method("pipx", "prowler", "prowler"),)),
    _tool("scoutsuite", "ScoutSuite", "cloud-container", "Review cloud configuration using credentials scoped to an approved account.", "scoutsuite", ("scout",), install_methods=(_method("pipx", "scoutsuite", "scout"),)),
    _tool("kube-hunter", "kube-hunter", "cloud-container", "Assess Kubernetes exposure only in clusters you own or have permission to test.", "kube-hunter", ("kube-hunter",), install_methods=(_method("pipx", "kube-hunter", "kube-hunter"),)),
    _tool("pacu", "Pacu", "cloud-container", "Assess AWS attack paths in a test account with explicit owner approval.", "pacu", ("pacu",), install_methods=(_method("pipx", "pacu", "pacu", "git+https://github.com/RhinoSecurityLabs/pacu.git"),)),
    _tool("roadrecon", "ROADrecon", "cloud-container", "Enumerate Microsoft Entra ID tenant data with approved credentials.", "roadrecon", ("roadrecon",), install_methods=(_method("pipx", "roadrecon", "roadrecon"),)),
    _tool("cloudfox", "CloudFox", "cloud-container", "Map attack paths in cloud accounts you own or are authorized to assess.", "cloudfox", ("cloudfox",), install_methods=(_method("go", "github.com/BishopFox/cloudfox", "cloudfox"),)),
    _tool("kube-bench", "kube-bench", "cloud-container", "Check Kubernetes configuration against security baselines on an approved cluster.", "kube-bench", ("kube-bench",), install_methods=(_method("go", "github.com/aquasecurity/kube-bench", "kube-bench"),)),

    # Mobile applications
    _tool("apktool", "Apktool", "mobile", "Decode Android application packages for an authorized mobile assessment.", "apktool", ("apktool",)),
    _tool("jadx", "JADX", "mobile", "Decompile Android applications for authorized source and behavior review.", "jadx", ("jadx",)),
    _tool("frida-tools", "Frida Tools", "mobile", "Instrument applications in an owned device or approved test environment.", "frida-tools", ("frida", "frida-ps"), install_methods=(_method("pipx", "frida-tools", "frida"),)),
    _tool("objection", "Objection", "mobile", "Explore mobile runtime behavior in an authorized test application.", "objection", ("objection",), install_methods=(_method("pipx", "objection", "objection"),)),

    # Forensics and reverse engineering
    _tool("ghidra", "Ghidra", "forensics-reversing", "Reverse-engineer binaries using a maintained analysis suite.", "ghidra", ("ghidra",)),
    _tool("radare2", "Radare2", "forensics-reversing", "Inspect and reverse engineer binaries and firmware.", "radare2", ("r2",)),
    _tool("volatility3", "Volatility 3", "forensics-reversing", "Analyze memory images supplied for an authorized investigation.", "volatility3", ("vol", "volatility")),
    _tool("binwalk", "Binwalk", "forensics-reversing", "Inspect firmware images and embedded file systems.", "binwalk", ("binwalk",)),
    _tool("foremost", "Foremost", "forensics-reversing", "Recover files from disk images provided for an authorized review.", "foremost", ("foremost",)),
    _tool("exiftool", "ExifTool", "forensics-reversing", "Review and edit file metadata during an authorized assessment.", "libimage-exiftool-perl", ("exiftool",)),
    _tool("yara", "YARA", "forensics-reversing", "Match supplied files against local research and detection rules.", "yara", ("yara",)),
    _tool("gdb", "GNU Debugger", "forensics-reversing", "Inspect and debug binaries from an authorized analysis or lab.", "gdb", ("gdb",), other_packages={"apk": "gdb"}),
    _tool("gdb-multiarch", "GDB Multiarch", "forensics-reversing", "Debug binaries built for multiple architectures in an isolated analysis lab.", "gdb-multiarch", ("gdb-multiarch",)),
    _tool("rizin", "Rizin", "forensics-reversing", "Inspect and reverse engineer binaries and firmware in an authorized lab.", "rizin", ("rizin", "rz")),
    _tool("checksec", "checksec", "forensics-reversing", "Review binary hardening properties in a controlled analysis environment.", "checksec", ("checksec",)),
    _tool("ropgadget", "ROPgadget", "forensics-reversing", "Inspect return-oriented programming gadget presence in lab binaries.", "ropgadget", ("ROPgadget",), install_methods=(_method("pipx", "ropgadget", "ROPgadget"),)),
    _tool("ropper", "Ropper", "forensics-reversing", "Search gadget sequences in binaries provided for authorized analysis.", "ropper", ("ropper",), install_methods=(_method("pipx", "ropper", "ropper"),)),
    _tool("pwntools", "pwntools", "forensics-reversing", "Build and inspect proof-of-concept binaries in isolated security labs.", "python3-pwntools", ("pwn",), install_methods=(_method("pipx", "pwntools", "pwn"),)),
    _tool("steghide", "Steghide", "forensics-reversing", "Inspect owned sample files for embedded data during a lab exercise.", "steghide", ("steghide",)),
    _tool("zsteg", "zsteg", "forensics-reversing", "Inspect owned PNG and BMP samples for embedded data.", "zsteg", ("zsteg",), install_methods=(_method("gem", "zsteg", "zsteg"),)),
    _tool("testdisk", "TestDisk / PhotoRec", "forensics-reversing", "Recover files from disk images provided for authorized analysis.", "testdisk", ("testdisk", "photorec")),
    _tool("sleuthkit", "The Sleuth Kit", "forensics-reversing", "Inspect disk images supplied for authorized forensic work.", "sleuthkit", ("fls", "mmls", "tsk_recover")),
    _tool("bulk-extractor", "bulk_extractor", "forensics-reversing", "Extract artifacts from forensic images supplied for review.", "bulk-extractor", ("bulk_extractor",)),
    _tool("scalpel", "Scalpel", "forensics-reversing", "Carve files from authorized disk images in a controlled analysis.", "scalpel", ("scalpel",)),
)

CATEGORY_BY_ID = {category.id: category for category in CATEGORIES}
TOOL_BY_ID = {tool.id: tool for tool in TOOLS}
TOOLS_BY_CATEGORY = {
    category.id: tuple(tool for tool in TOOLS if tool.category_id == category.id)
    for category in CATEGORIES
}
