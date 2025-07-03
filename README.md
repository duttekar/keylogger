# keylogger
==================================================
               C KEYLOGGER PROJECT
==================================================

Author      : Yash Mistry and Dwip Uttekar
Language    : C (Windows API)
Purpose     : For educational & ethical cybersecurity training
Last Update : May, 2025 

==================================================
⚠️ DISCLAIMER
==================================================
This project is strictly intended for **educational purposes** and **authorized cybersecurity training/lab use** ONLY.

❗ DO NOT use this software to monitor systems you do not own or lack explicit permission to analyze.

Unauthorized use of keyloggers is illegal and punishable under cybercrime laws.

The developer takes **no responsibility** for any damages or misuse of this software.

==================================================
🎯 PROJECT OVERVIEW
==================================================
This C-based keylogger uses Windows API functions to:
- Monitor and log keystrokes in the background
- Capture active window titles with timestamps
- Automatically hide the console window
- Store logs in a hidden file named `winupdate.txt`
- Attempt periodic FTP upload to a remote server
- Set persistence via registry and startup folder
- Detect multiple instances using mutex
- Check internet connection status before upload

This is a complete, advanced keylogger written for demonstration and testing in a **controlled environment**.

==================================================
📁 FILES & STRUCTURE
==================================================
Main Code File   : keylogger.c  
Output Log File  : %USERPROFILE%\Documents\winupdate.txt  
Startup Copy     : %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\SystemCore.exe

Important Notes:
- Uses `WinMain` to run silently as a Windows GUI process
- Creates a registry key in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- FTP credentials and path are **hardcoded** for test environments

==================================================
🛠️ DEPENDENCIES
==================================================
Libraries used:
- wininet.lib
- psapi.lib
- shell32.lib
- user32.lib
- advapi32.lib

Tested Environment:
- Windows 10/11 (x64)
- Visual Studio / MinGW

Compile with:
- Linker flag: `/SUBSYSTEM:WINDOWS /ENTRY:WinMain`
- Link to: `wininet.lib`, `user32.lib`, `psapi.lib`, `shell32.lib`

==================================================
🚀 HOW TO RUN (TESTING ONLY)
==================================================
1. Compile the source using Visual Studio or MinGW with required libraries (recommended: Codeblock).
2. Run the binary (ensure admin privileges for registry operations).
3. Logs will be stored in the user Documents folder as `winupdate.txt`.
4. The log will be uploaded via FTP every 15 seconds (if online).

⚠️ This project should ONLY be executed inside a sandboxed VM environment or testing lab.

==================================================
🔐 SECURITY CONSIDERATIONS
==================================================
This tool includes:
- Stealth persistence mechanisms
- System process disguise
- FTP-based log uploading
- Internet connection checks
- Active window logging
- Process name capture

Make sure to review all source code thoroughly before compiling. Do **not** compile or run on production or public systems.

==================================================
📜 LICENSE
==================================================
This project is released under the MIT License.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files...

Copyright © 2025 Yash Mistry and Dwip Uttekar

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

==================================================
📢 FINAL REMARK
==================================================
This is a powerful demonstration tool designed for:
- Red teaming labs
- Malware analysis classes
- Ethical hacking practice
- Cybersecurity awareness sessions

Use it responsibly. Always act within legal boundaries.
