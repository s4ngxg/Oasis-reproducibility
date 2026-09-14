
# ParaSwap

**Environment: Ubuntu >=18.04**

This repository contains implementations of two fundamental building blocks in ParaSwap. The projects included are:
1. Two-party computation protocol of adaptor signature in ParaSwap, refer to `two-party computation`.
2. Verifiable timed discrete logarithm (VTD) in ParaSwap, refer to `VTD`.

The implementation of two-party computation with instantiations based on Schnorr signature builds up on the implementation of A2L [1], and the implementation of VTD builds up on the implementation of Homomorphic Time-Lock Puzzles and Applications [2]. 

## Two-party computation
### Dependencies for two-party computation
* **[CMake](https://cmake.org/download/)  >= 3.10.2**
```
wget https://cmake.org/files/v3.10/cmake-3.10.2-Linux-x86_64.tar.gz
tar zxvf cmake-3.10.2-Linux-x86_64.tar.gz
sudo mv cmake-3.10.2-Linux-x86_64 /usr/share/cmake-3.10
sudo ln -sf /usr/share/cmake-3.10/bin/* /usr/bin/   # create global symlinks
cmake --version # expected output: "cmake version 3.10.2"
```

* **[ZeroMQ](https://github.com/zeromq/libzmq) 4.1.7**
**Before installing ZeroMQ, ensure that the following packages are installed:**
```
sudo apt-get install libtool
sudo apt-get install pkg-config
sudo apt-get install build-essential
sudo apt-get install autoconf
sudo apt-get install automake
```
**Once the prerequisite packages are installed, follow these steps to install ZeroMQ:**
```
wget https://github.com/zeromq/zeromq4-1/releases/download/v4.1.7/zeromq-4.1.7.tar.gz
tar -xvf zeromq-4.1.7.tar.gz
cd zeromq-4.1.7
./configure
sudo make
sudo make install
sudo ldconfig
```

* **[GMP](https://gmplib.org/)  6.2.1**
* **[RELIC](https://github.com/relic-toolkit/relic/wiki/Building) (configured and built with `-DARITH=gmp`)**
* **[PARI/GP](https://pari.math.u-bordeaux.fr/)  2.13.4**
### How to run code of two-party computation
First, compile CMakeLists.txt, then run bin/bob (i.e., ./bob) directly, and then run bin/tumbler (i.e., ./tumbler)


## VTD
### Dependencies for VTD
* **[Shamir secret sharing](https://github.com/dsprenkels/sss)**
**Clone from git by the command below. (As it is recommended. If you clone, make sure that the file under the subdirectory also comes with it.**
```
git clone --recursive https://github.com/dsprenkels/sss.git
```
**Build &** **Install**
```
cd sss
make
```

* **[libsodium](https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz) 1.0.18**
```
git clone git://github.com/jedisct1/libsodium.git
```
**Build &** **Install**:
```
cd libsodium
./autogen.sh -s
./configure && make check
sudo make install 
sudo ldconfig  # Reload dynamic libraries
```

* **[GCC](https://gcc.gnu.org/install/download.html) 11.4.0**
* **[Openssl](https://openssl-library.org/source/) 3.0.2**
* **[GMP](https://gmplib.org/)  6.2.1**

### How to run code of VTD
```
gcc vtd.c -o vtd \
  -Iinclude \
  -Llib -llhp -lsss \
  -lgmp -lssl -lcrypto -lsodium
```


## Baseline (HtlcSwap)
This repository contains implementations of baseline (HtlcSwap [3])
### How to use
Deploy on [Remix](https://remix.ethereum.org/)
1. Firstly, adjust the contract parameters, including the number of hash locks for participating parties, the threshold value for signatures, and the time parameter.
2. Afterwards, input the necessary inputs for deployment, including transfer amount, hash lock, signature public key, sender address, and receiver address.
3. After completing the deployment, you can choose to transfer or refund. For transfer, it needs to be called before the time lock arrives, and input the correct hash lock secret value and signature parameters v, r, s. After the time lock is reached, timeout can be called to implement Refund.

Note that for convenience, this contract repeatedly uses a pair of hash lock and signature as the hash lock group and the private key signature of the participant respectively.

### An example of input

|        |                                                                    |
| ------ | ------------------------------------------------------------------ |
| hash   | 0xaaa56799aebb7de173afec4380731b2a56035a7ed1b757b940de470c24450d38 |
| pkey   | 0x827330B5B4CA1806271cE813031Ab40bDf95000a                         |
|        |                                                                    |
| secret | 0x4b1776f95a3547e1beda79a1acc82276d2d1eba013ea268cc2d2b219b25e940c |
| v      | 0x1c                                                               |
| r      | 0x4693ad02a07805c0a20ad630883cf7e710dc686c2fb332643ba699de8a17e679 |
| s      | 0x670be8e273c7b712f4b5e91db59f4a9b813f20fee13bacc4f04d210f8fc2f810 |

## References

[1] Erkan Tairi, Pedro-Moreno Sanchez, and Matteo Maffei, "[A2L: Anonymous Atomic Locks for Scalability and Interoperability in Payment Channel Hubs](https://eprint.iacr.org/2019/589)".

[2] Malavolta, Giulio, and Sri Aravinda Krishnan Thyagarajan, "[Homomorphic time-lock puzzles and applications.](https://eprint.iacr.org/2019/635.pdf)"

[3] Soichiro Imoto, Yuichi Sudo, Hirotsugu Kakugawa, and Toshimitsu Masuzawa, "[Atomic cross-chain swaps with improved space, time and local time complexities](https://arxiv.org/pdf/1905.09985)".