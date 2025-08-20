# Week 6 Quiz: Network Security

**Total Points**: 25 points  
**Time Limit**: 30 minutes  
**Format**: 5 True/False (1pt each), 10 Multiple Choice (1pt each), 5 Short Answer (2pts each)

---

## Part A: True/False Questions (5 points)
*1 point each. Write T for True or F for False.*

**1.** TLS 1.3 provides forward secrecy by default.  
**Answer**: ______

**2.** A VPN always provides end-to-end encryption for all network traffic.  
**Answer**: ______

**3.** Firewalls can inspect and filter encrypted HTTPS traffic without additional tools.  
**Answer**: ______

**4.** DNS over HTTPS (DoH) helps prevent DNS queries from being monitored by network providers.  
**Answer**: ______

**5.** Network Address Translation (NAT) provides security through obscurity but is not a security control.  
**Answer**: ______

---

## Part B: Multiple Choice Questions (10 points)
*1 point each. Choose the best answer.*

**6.** Which layer of the OSI model does TLS operate at?
- A) Layer 3 (Network)
- B) Layer 4 (Transport)
- C) Layer 5 (Session)
- D) Layer 7 (Application)

**Answer**: ______

**7.** What is the primary purpose of a DMZ in network security?
- A) To provide faster internet access
- B) To isolate public-facing servers from internal networks
- C) To encrypt network traffic
- D) To backup network configurations

**Answer**: ______

**8.** Which attack involves flooding a network with traffic to make it unavailable?
- A) Man-in-the-middle
- B) SQL injection
- C) Distributed Denial of Service (DDoS)
- D) Buffer overflow

**Answer**: ______

**9.** What does perfect forward secrecy ensure?
- A) Encrypted data remains secret even if long-term keys are compromised
- B) Network traffic is always encrypted
- C) Keys are never transmitted over the network
- D) Encryption is unbreakable

**Answer**: ______

**10.** Which protocol is commonly used for secure remote access to servers?
- A) Telnet
- B) SSH
- C) FTP
- D) HTTP

**Answer**: ______

**11.** What is the main difference between a packet filter firewall and a stateful firewall?
- A) Speed of operation
- B) Stateful firewalls track connection state
- C) Cost of implementation
- D) Number of supported protocols

**Answer**: ______

**12.** Which network security measure helps prevent ARP poisoning attacks?
- A) HTTPS
- B) Static ARP tables
- C) DNS filtering
- D) Port scanning

**Answer**: ______

**13.** What is network segmentation?
- A) Dividing network cables into segments
- B) Separating networks into isolated zones
- C) Encrypting network segments
- D) Backing up network configurations

**Answer**: ______

**14.** Which tool is commonly used for network intrusion detection?
- A) Wireshark
- B) Snort
- C) Nmap
- D) Metasploit

**Answer**: ______

**15.** What does certificate pinning prevent in network security?
- A) DDoS attacks
- B) Man-in-the-middle attacks with rogue certificates
- C) SQL injection
- D) Buffer overflow attacks

**Answer**: ______

---

## Part C: Short Answer Questions (10 points)
*2 points each. Answer in 1-2 sentences.*

**16.** Explain the difference between a network-based IDS and a host-based IDS.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**17.** What is SSL stripping and how can it be prevented?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**18.** Describe the security benefits and limitations of using a VPN.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**19.** What is BGP hijacking and why is it a significant security threat?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**20.** Explain how zero-trust network architecture differs from traditional perimeter security.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

---

## Answer Key (Instructor Use Only)

### Part A: True/False
1. **T** - TLS 1.3 mandates perfect forward secrecy
2. **F** - VPN encrypts traffic between client and VPN server, not necessarily end-to-end
3. **F** - Firewalls cannot inspect encrypted content without decryption capabilities
4. **T** - DoH encrypts DNS queries to prevent monitoring
5. **T** - NAT provides some obscurity but is not a true security control

### Part B: Multiple Choice
6. **C** - Layer 5 (Session) - TLS operates between transport and application layers
7. **B** - To isolate public-facing servers from internal networks
8. **C** - Distributed Denial of Service (DDoS)
9. **A** - Encrypted data remains secret even if long-term keys are compromised
10. **B** - SSH (Secure Shell)
11. **B** - Stateful firewalls track connection state
12. **B** - Static ARP tables
13. **B** - Separating networks into isolated zones
14. **B** - Snort (IDS/IPS)
15. **B** - Man-in-the-middle attacks with rogue certificates

### Part C: Short Answer (Sample Answers)
16. Network-based IDS monitors traffic across network segments and can detect attacks targeting multiple hosts, while host-based IDS runs on individual systems and can detect local attacks and system-level changes that network IDS might miss.

17. SSL stripping is an attack that downgrades HTTPS connections to HTTP to intercept data. It can be prevented using HTTP Strict Transport Security (HSTS) headers that force browsers to use HTTPS connections.

18. VPNs provide encrypted tunnels and can hide IP addresses, offering privacy and protection on untrusted networks, but they create a single point of failure, may log user activity, and don't protect against malware or provide end-to-end encryption for application data.

19. BGP hijacking involves maliciously advertising IP address prefixes to redirect internet traffic through an attacker's infrastructure. It's significant because it can enable mass surveillance, traffic interception, and distributed attacks while being difficult to detect quickly.

20. Zero-trust architecture assumes no implicit trust based on network location and continuously verifies every user and device, while traditional perimeter security trusts everything inside the network boundary and focuses on defending the perimeter.

---

## Grading Rubric

| Section | Points | Scoring |
|---------|--------|---------|
| True/False | 5 | 1 point per correct answer |
| Multiple Choice | 10 | 1 point per correct answer |
| Short Answer | 10 | 2 points per answer: Full (2), Partial (1), Incorrect (0) |
| **Total** | **25** | |

### Short Answer Grading Guidelines:
- **2 points**: Complete, accurate answer demonstrating understanding
- **1 point**: Partially correct or incomplete answer
- **0 points**: Incorrect or no answer

### Grade Scale:
- A: 23-25 points (92-100%)
- B: 20-22 points (80-91%)
- C: 18-19 points (72-79%)
- D: 15-17 points (60-71%)
- F: Below 15 points (<60%)