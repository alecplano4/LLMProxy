# Enhanced Wikipedia Search
This project supplants Wikipedia's native search functionality with 
search results that incorporate semantic understanding via ChatGPT's LLM

---

## Table of Contents

1. [Features](#Features)
2. [Installation](#Installation)
3. [Execution](#Execution)
4. [Usage](#Usage)
5. [Acknowledgements](#Acknowledgements)

---

## Features
- Add semantic understanding to Wikipedia's search functionality!

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/alecplano4/LLMProxy
   ```
2. Add ca.cert to list of trusted Certificate Authorities (CA's)
3. Route browser traffic through proxy (set browser proxy IP address to: 127.0.0.1 and port to 9120)

## Execution
1. Compile code
```bash
make proxy.out
```
2. Execute code
```bash
./proxy.out 9120
```

## Usage
In browser, navigate web normally. To test Wikipedia search functionality, navigate to Wikipedia's
search (https://www.wikipedia.org/) and request any query. Enjoy the results!

## Acknowledgements
Alec and Sam are greatful to Professor Fahad Dogar and Abdullah Faisal for their 
many contributions to this project.