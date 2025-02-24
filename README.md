# IOCTLance
<p align="center">
  <img src="asset/ioctlance.png">
</p>

## Description
Presented at [CODE BLUE 2023](https://codeblue.jp/2023/en/), this project titled [Enhanced Vulnerability Hunting in WDM Drivers with Symbolic Execution and Taint Analysis](https://drive.google.com/file/d/1lEegyJ1SBB_lDts6F3W3JPySucM3nugR/view?usp=sharing) introduces IOCTLance, a tool that enhances its capacity to detect various vulnerability types in Windows Driver Model (WDM) drivers. In a comprehensive evaluation involving 104 known vulnerable WDM drivers and 328 unknown ones, IOCTLance successfully unveiled 117 previously unidentified vulnerabilities within 26 distinct drivers. As a result, 41 CVEs were reported, encompassing 25 cases of denial of service, 5 instances of insufficient access control, and 11 examples of elevation of privilege.

## Features
### Target Vulnerability Types
- map physical memory
- controllable process handle
- buffer overflow
- null pointer dereference
- read/write controllable address
- arbitrary shellcode execution
- arbitrary wrmsr
- arbitrary out
- dangerous file operation


### Optional Customizations
- length limit
- loop bound
- total timeout
- IoControlCode timeout
- recursion
- symbolize data section


## Build
### Docker (Recommand)
```
docker build .
docker run -it <IOCTLance IMAGE ID> bash
```

### Local
```
dpkg --add-architecture i386
apt-get update
apt-get install git build-essential python3 python3-pip python3-dev htop vim sudo \
                openjdk-8-jdk zlib1g:i386 libtinfo5:i386 libstdc++6:i386 libgcc1:i386 \
                libc6:i386 libssl-dev nasm binutils-multiarch qtdeclarative5-dev libpixman-1-dev \
                libglib2.0-dev debian-archive-keyring debootstrap libtool libreadline-dev cmake \
                libffi-dev libxslt1-dev libxml2-dev

pip install angr==9.2.18 ipython==8.5.0 ipdb==0.13.9
```

## Analysis
```
# python3 analysis/ioctlance.py -h
usage: ioctlance.py [-h] [-i IOCTLCODE] [-T TOTAL_TIMEOUT] [-t TIMEOUT] [-l LENGTH] [-b BOUND]
                    [-g GLOBAL_VAR] [-a ADDRESS] [-e EXCLUDE] [-o] [-r] [-c] [-d]
                    path

positional arguments:
  path                  dir (including subdirectory) or file path to the driver(s) to analyze

optional arguments:
  -h, --help            show this help message and exit
  -i IOCTLCODE, --ioctlcode IOCTLCODE
                        analyze specified IoControlCode (e.g. 22201c)
  -T TOTAL_TIMEOUT, --total_timeout TOTAL_TIMEOUT
                        total timeout for the whole symbolic execution (default 1200, 0 to unlimited)
  -t TIMEOUT, --timeout TIMEOUT
                        timeout for analyze each IoControlCode (default 40, 0 to unlimited)
  -l LENGTH, --length LENGTH
                        the limit of number of instructions for technique LengthLimiter (default 0, 0
                        to unlimited)
  -b BOUND, --bound BOUND
                        the bound for technique LoopSeer (default 0, 0 to unlimited)
  -g GLOBAL_VAR, --global_var GLOBAL_VAR
                        symbolize how many bytes in .data section (default 0 hex)
  -a ADDRESS, --address ADDRESS
                        address of ioctl handler to directly start hunting with blank state (e.g.
                        140005c20)
  -e EXCLUDE, --exclude EXCLUDE
                        exclude function address split with , (e.g. 140005c20,140006c20)
  -o, --overwrite       overwrite x.sys.json if x.sys has been analyzed (default False)
  -r, --recursion       do not kill state if detecting recursion (default False)
  -c, --complete        get complete base state (default False)
  -d, --debug           print debug info while analyzing (default False)
```


## Evaluation
```
# python3 evaluation/statistics.py -h
usage: statistics.py [-h] [-w] path

positional arguments:
  path        target dir or file path

optional arguments:
  -h, --help  show this help message and exit
  -w, --wdm   copy the wdm drivers into <path>/wdm
```


## Test
1. Compile the testing examples in [test](./test) to generate testing driver files.
2. Run IOCTLance against the drvier files.


## Reference
- [ucsb-seclab/popkorn-artifact](https://github.com/ucsb-seclab/popkorn-artifact)
- [eclypsium/Screwed-Drivers](https://github.com/eclypsium/Screwed-Drivers)
- [koutto/ioctlbf](https://github.com/koutto/ioctlbf)
- [Living Off The Land Drivers](https://www.loldrivers.io/)