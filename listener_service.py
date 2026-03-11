import re
import select
import subprocess
import ipaddress
from systemd import journal

# Determines which strings to look for
SSH_SERVICE_NAME = "ssh.service" # some distros might call it sshd.service
SSH_HAS_PASS_AUTH_DISABLED = False

# nftables consts

NFT_SETUP_FILE = "./ssh_auto_ban-default.nft" # in the real world, this needs to be installed and root-only.
TABLE = "ssh_auto_bans"
SET_V4 = "banned_v4"
SET_V6 = "banned_v6"
TIMEOUT = "12h"

# Strings to search for in the sshd log

# I'm still unsure where to put the "Connection closed by authenticating user" one - it still applies as long as theres key auth but will duplicate those who try pw auth

INVALID_USER_RE = re.compile(r"(Invalid user|Connection closed by authenticating user) (\S*)( from)? (\S+) port .*") # match auths against nonexistent users or giving-up users (only match these if password auth is disabled, else they'll be double counted)
FAILED_RE = re.compile(r"(Unable to negotiate with|banner exchange: Connection from) (\S+) port .*") # Failures for reasons other than incorrect password, which are unlikely to be legit user errors
PASS_INCORRECT_RE = re.compile("Failed password for( invalid user)? (\S+) from (\S+) port .*")
ACCEPT_RE = re.compile(r"Accepted (\S+) for (\S+) from (\S+)")

def ban_bad_ip(ip):
    addr = ipaddress.ip_address(ip)

    if addr.version == 4:
        setname = "banned_v4"
    else:
        setname = "banned_v6"

    subprocess.run(
        [
            "nft",
            "add",
            "element",
            "inet",
            "ssh_auto_bans",
            setname,
            f"{{ {ip} timeout {TIMEOUT} }}"
        ],
        check=False
    )
    print(f"Banned ip {ip}")

def handle_bad_ip(ip):
    print(f"Bad IP detected: {ip}")
    # todo, actually connect it to the reputation checker
    ban_bad_ip(ip)

def extract_ip(msg):
    #Return IP if message indicates a failure or incorrect pass
    m = PASS_INCORRECT_RE.search(msg)
    if m:
        return m.group(3)

    # It's redundant to check this if ssh has password authentication enabled
    if SSH_HAS_PASS_AUTH_DISABLED:
        m = INVALID_USER_RE.search(msg)
        if m:
            return m.group(4)

    m = FAILED_RE.search(msg)
    if m:
        return m.group(2)

    return None


def main():
    # initialize the nftables table for ip bans
    subprocess.run(["nft", "-f", NFT_SETUP_FILE], check=False)


    j = journal.Reader()
    j.add_match(_SYSTEMD_UNIT=SSH_SERVICE_NAME)

    j.seek_tail()
    j.get_next()

    poller = select.poll()
    poller.register(j.fileno(), select.POLLIN)


    while True:
        poller.poll()

        if j.process() != journal.APPEND:
            continue

        for entry in j:
            msg = entry.get("MESSAGE", "")

            ip = extract_ip(msg)
            if ip:
                handle_bad_ip(ip)


if __name__ == "__main__":
    main()
