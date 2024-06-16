# APSU

## Introduction
APSU is an unbalanced PSU protocol which is described in [eprint.iacr.org/2022/653](https://eprint.iacr.org/2022/653). The larger difference betweend the sizeof of two sets, the better our protocol performs.    


## How to build

Our `APSU` is amended form [APSI](https://github.com/microsoft/APSI), so you may use for reference the method of build `APSI` to compile `APSU`. 

### vcpkg
[vcpkg](https://github.com/microsoft/vcpkg) can help you manange C and C++ libraries on Windows, Linux and MacOS. We recommend to build and install dependencies for `APSU ` with vcpkg.  
Some Dependencies which are needed by building APSU are as follows. 

| Dependency                                                | vcpkg name                                           |
|-----------------------------------------------------------|------------------------------------------------------|
| [Microsoft SEAL](https://github.com/microsoft/SEAL)       | `seal[no-throw-tran]`                                |
| [Microsoft Kuku](https://github.com/microsoft/Kuku)       | `kuku`                                               |
| [Log4cplus](https://github.com/log4cplus/log4cplus)       | `log4cplus`                                          |
| [cppzmq](https://github.com/zeromq/cppzmq)                | `cppzmq` (needed only for ZeroMQ networking support) |
| [FlatBuffers](https://github.com/google/flatbuffers)      | `flatbuffers`                                        |
| [jsoncpp](https://github.com/open-source-parsers/jsoncpp) | `jsoncpp`                                            |
| [TCLAP](https://sourceforge.net/projects/tclap/)          | `tclap` (needed only for building CLI)               |
| [OpenSSL](https://www.openssl.org/)                       | `openssl`                                            |



First follow this [Quick Start on Unix](https://github.com/microsoft/vcpkg#quick-start-unix), and then run:
```powershell
./vcpkg install [package name]:x64-linux
```


To build your CMake project with dependency on APSU, follow [this guide](https://github.com/microsoft/vcpkg#using-vcpkg-with-cmake).

### libOTe
[libOTe](https://github.com/osu-crypto/libOTe) is a  fast and portable C++17 library for Oblivious Transfer extension (OTe). We can build it by following commands.
```
git clone --recursive https://github.com/osu-crypto/libOTe.git
cd libOTe
python build.py --setup --all --boost --relic
python build.py -DENABLE_SODIUM=OFF -DENABLE_MRR_TWIST=OFF -DENABLE_RELIC=ON --install=/your/path/libOTe
```

#### Notes 
1. LibOTE Releases 2.2.0 removed support of C++ 17, 14, so we recommand to use the old version, e.g. Releases 2.1.0 and earlier.
2. `libzmq` has some conflict with libsodium. Please disable libsodium and replace it with librelic. You can refer README.md of libOTe for details. 
3. Default install folder of  `libOTe` is `thirdparty/`. You can change this setting and pass the following arguments to CMake when configure: `-DLIBOTE_PATH=/your/path/libOTe`


### Kunlun
[Kunlun](https://github.com/yuchen1024/Kunlun) is an efficient and modular crypto library. We have embedded ```Kunlun``` into our code which is a head-only library, so you do not need to build or install ```Kunlun```. 
### APSU
When you have all dependencies ready, you can build APSU by the following commands. 
```
git clone https://github.com/real-world-cryprography/APSU.git
cd APSU
mkdir build
cd build
cmake .. -DLIBOTE_PATH=/your/path
cmake --build . 

```
## Command-Line Interface (CLI)
Same as `APSI`, out APSU comes with example command-line programs implementing a sender and a receiver.
In this section we describe how to run these programs.

### Common Arguments

The following optional arguments are common both to the sender and the receiver applications.

| Parameter | Explanation |
|-----------|-------------|
| `-t` \| `--threads` | Number of threads to use |
| `-f` \| `--logFile` | Log file path |
| `-s` \| `--silent` | Do not write output to console |
| `-l` \| `--logLevel` | One of `all`, `debug`, `info` (default), `warning`, `error`, `off` |

### Sender

The following arguments specify the receiver's behavior.

| Parameter | Explanation |
|-----------|-------------|
| `-q` \| `--queryFile` | Path to a text file containing query data (one per line) |
| `-a` \| `--ipAddr` | IP address for a sender endpoint |
| `--port` | TCP port to connect to (default is 1212) |

### Receiver

The following arguments specify the sender's behavior and determine the parameters for the protocol.
In our CLI implementation the sender always chooses the parameters and the receiver obtains them through a parameter request.
Note that in other applications the receiver may already know the parameters, and the parameter request may not be necessary.

| <div style="width:190px">Parameter</div> | Explanation |
|-----------|-------------|
| `-d` \| `--dbFile` | Path to a CSV file describing the sender's dataset (an item-label pair on each row) or a file containing a serialized `SenderDB`; the CLI will first attempt to load the data as a serialized `SenderDB`, and &ndash; upon failure &ndash; will proceed to attempt to read it as a CSV file |
| `-p` \| `--paramsFile` | Path to a JSON file [describing the parameters](#loading-from-json) to be used by the sender
| `--port` | TCP port to bind to (default is 1212) |


### AutoTest
We have prapared an automated testing tool in the folder `\tools`. You could test whether APSU protocol works successlfully.