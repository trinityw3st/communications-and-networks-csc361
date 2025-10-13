# Assignment 1 — WebTester

## 🧠 Overview

This project implements a **simple web client** that analyzes HTTP and HTTPS connections for a given URI. It uses **low-level socket programming** and **TLS/SSL connections** to examine a web server’s behavior, including:

The program mimics a lightweight browser, making raw HTTP and HTTPS requests, parsing responses, and printing formatted connection details.

**WebTester** is a Python command-line tool that checks a website’s:
- HTTP/2 support  
- Cookies  
- Password protection  

It does this using **raw sockets** and **TLS**—no external HTTP libraries.

---

## 🚀 Features
- Parses and validates URIs (`http` or `https`)
- Connects via raw TCP or TLS
- Detects HTTP/2 using ALPN negotiation
- Extracts and formats `Set-Cookie` headers
- Detects password protection (`401` + `WWW-Authenticate`)
- Follows redirects (301/302)
- Prints a clear summary of:
  - Host  
  - HTTP/2 support  
  - Cookies  
  - Password protection  

---

## 📦 Structure
WebTester/
├── WebTester.py # Main script
├── WebTesterClasses.py # Defines URI and Cookie classes
└── README.md


---

## 🧰 Requirements
Works with **Python 3** only.  
Uses standard libraries:
- `sys`
- `socket`
- `ssl`
- `urllib.parse`

_No external dependencies._

---

## ⚙️ Usage

### Basic command
```
python3 WebTester.py [uri]
```

### 🧪 Examples

```
python3 WebTester.py https://www.uvic.ca
python3 WebTester.py www.example.com
```

### 🧠 Local Testing

Run the program locally using one of the following commands:

```
python3 WebTester.py 127.0.0.1:8000/
python3 WebTester.py http://127.0.0.1:8000/
```

### 💻 Example Output
```
---Request begin---
GET / HTTP/1.1
Host: www.uvic.ca

Connection: Keep-Alive

---Request end---
HTTP request sent, awaiting response...

---Response Header---
HTTP/1.1 200 OK
Set-Cookie: sessionid=12345; domain=.uvic.ca; expires=Wed, 16-Oct-2024 20:15:00 GMT

---Response Body---
website: www.uvic.ca

Supports http2: True

List of Cookies:
Cookie name: sessionid, expires: Wed, 16-Oct-2024 20:15:00 GMT, domain: .uvic.ca

Password-protected: False
```


