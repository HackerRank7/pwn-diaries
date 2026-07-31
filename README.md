# Packed Light — TryHackMe (HackerHolidays)

![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green) ![Category](https://img.shields.io/badge/Category-Forensics-blue) ![Points](https://img.shields.io/badge/Points-60-orange)

## 📌 Overview
- **Platform:** TryHackMe — HackerHolidays Event
- **Difficulty:** Easy
- **Category:** Forensics / PCAP Analysis / Cryptography
- **Points:** 60

**Scenario:** A short packet capture from the hotel guest network shows small, suspiciously regular outbound packets — like data being smuggled out in tiny, disguised chunks. The task is to find the covert channel, reassemble the hidden data, decode it, and recover the flag.

**Attack path summary:** A malicious Python script (`updates.py`) running on a guest machine exfiltrates the flag one XOR + Base64-encoded word at a time, hidden inside an HTTP `Cookie` header (`hotel_sess_state`) sent on a loop to an external server on port 8080.

---

## 🔍 Initial Analysis (Wireshark)

Opened `traffic.pcapng` in Wireshark. Noticed repeated small TCP connections on port `8080` between the guest host `192.168.1.141` and an external IP `34.41.103.191`, along with local loopback noise on `127.0.0.1`.

📸 *(Packet list showing repeated 8080 connections and loopback traffic)*

<img width="1274" height="749" alt="Screenshot_2026-07-31_07-36-31" src="https://github.com/user-attachments/assets/997c30a4-0245-46cc-9ce0-b901cba79cce" />


## 📂 Finding the Dropped Script

Went to **File → Export Objects → HTTP** to list every file transferred over HTTP in the capture.

Found a suspicious file:

| Packet | Hostname | Content Type | Size | Filename |
|--------|----------|--------------|------|----------|
| 19 | byte-lotus-hotel.thm:8080 | text/x-python | 1,086 bytes | `updates.py` |

This stood out immediately — a `.py` file being served/transferred is not something a hotel network service would normally do. Exporting and reading it confirmed it was a script that reads a secret, XOR + Base64-encodes it in chunks, and sends each chunk out disguised as a session cookie.

📸 *(Export Object list highlighting updates.py)*

<img width="1268" height="754" alt="Screenshot_2026-07-31_07-42-16" src="https://github.com/user-attachments/assets/98232651-00c9-4280-a2a6-2f37e61d9d16" />


## 🍪 Extracting the Covert Channel (Cookie Exfiltration)

Filtered specifically for the outbound requests carrying the exfiltration cookie:

```bash
tshark -r traffic.pcapng -Y 'tcp.port == 8080 && http.request && http.cookie' -T fields -e http.cookie
```

This returned one `hotel_sess_state=<base64>` cookie per HTTP request — each one a separate small chunk of encoded data, sent on a loop.

📸 *(Wireshark filter tcp.port==8080 && http.request && http.cookie showing repeated GET / requests)*

<img width="1274" height="749" alt="Screenshot_2026-07-31_07-36-31" src="https://github.com/user-attachments/assets/cb982231-8661-4e81-a854-25ac0211da09" />


## 🧩 Cleaning & Reassembling the Data

Stripped the `hotel_sess_state=` prefix and joined every chunk into a single Base64 blob:

```bash
tshark -r traffic.pcapng -Y 'tcp.port == 8080 && http.request && http.cookie' -T fields -e http.cookie \
  | sed 's/^hotel_sess_state=//' \
  | tr -d '\n'
```

**Reassembled Base64 string:**
```
HA==AA==BQ==Mw==Hg==ew==Og==fA==Fw==eQ==Ow==Fw==Pw==fA==PA==Kw==IA==eQ==Jg==Lw==Fw==eA==Pg==LQ==Gg==Fw==MQ==eA==PQ==NQ==
```

---

## 🔓 Decoding (CyberChef)

Since `updates.py` XOR-encoded the data before Base64-encoding it, the recipe needed two steps in CyberChef:

1. **From Base64** (alphabet: `A-Za-z0-9+/=`, remove non-alphabet chars)
2. **XOR** — Key: `H` (UTF8), Standard scheme

Baking this recipe on the reassembled string revealed the flag in plaintext.

📸 *(CyberChef recipe: From Base64 → XOR with key 'H', output showing flag)*

<img width="1276" height="644" alt="Screenshot_2026-07-31_07-52-59" src="https://github.com/user-attachments/assets/ec4edeee-d978-4603-a462-145eee3017c7" />


## 🏁 Flag

```
THM{V3r4_1s_w4tch1ng_0veR_y0u}
```

---

## 🧠 Key Learnings

- Covert exfiltration channels don't always need custom protocols — abusing a common, ignorable HTTP header (like `Cookie`) with tiny, "boring-looking" repeated requests is a simple but effective way to hide data in plain sight.
- **Export Objects (HTTP)** in Wireshark is a fast way to spot anomalous file transfers (like a `.py` script) hiding among normal-looking traffic.
- Combining `tshark` field extraction with basic Unix text tools (`sed`, `tr`) is an efficient way to pull and reassemble scattered data before feeding it into a decoder.
- Recognizing a double-encoding scheme (XOR **then** Base64) is key — decoding only the outer layer (Base64) isn't enough; you have to reverse each layer in the correct order.

---

## 🛠️ Tools Used

`Wireshark` `tshark` `sed` `tr` `CyberChef`

---

## 🔗 Reference

- [Packed Light — TryHackMe HackerHolidays](https://tryhackme.com/room/packedlight) <!-- update with actual room URL -->
