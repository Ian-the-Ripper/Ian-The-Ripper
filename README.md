![Screenshot (325)](https://github.com/user-attachments/assets/2b86c083-bdcc-4eb6-9b50-a3958416233c)

# Ian The Ripper 🔓🕷️

Key Features of Ian the Ripper

**Advanced Attack Mode:**

Dictionary attacks with rule-based mutations

Brute force with customizable character sets

Mask attacks (e.g., ?l?l?d?d for two letters + two digits)

Hybrid attacks combining wordlists and masks

Performance Optimization:

Multi-threading support

GPU acceleration (via OpenCL)

Distributed computing capabilities

Session saving/resuming

Hash Support:

12+ hash algorithms (MD5 to SHA-3)

Automatic hash identification

Salted hash support

Advanced Features:

Comprehensive rule engine (like Hashcat's)

Real-time statistics

Benchmark mode

Session management

Cross-platform support

User Interface:

Detailed progress reporting

Verbose output modes

Session saving/loading

Results exporting

Usage Examples:
Dictionary Attack:

text
python Ian-The-Ripper.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -w rockyou.txt
Brute Force Attack:

text
python Ian-The-Ripper.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -b --min-length 4 --max-length 6
Mask Attack:

text
python Ian-The-Ripper.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -m "?l?l?l?d?d"
Session Management:

text
python Ian-The-Ripper.py --session my_session.json




How to install 

git clone https://github
