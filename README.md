# Indigo

### A high performance, end to end encrypted LAN file transfer tool.
Indigo is a file transfer program for local networks, it detects available devices in each available network  
and can send selected files to these peers, fast and securely.

### Goals of this project.
#### The goals of this project are listed below, in order of importance

#### 1. Data safety and end to end encryption
  Secure, secret and reliable communications is the initiative that brought this project to life.  
  We created a secure cryptosystem, against attackers. No one should be able to get any kind of information  
  about the content of the files transferred, and no one should be able to impersonate another user in the network.
#### 2. Easy to use
  A tool that the user can't use is a tool that didn't keep its promise to do its job.
#### 3. High speed, low memory
  The lower the requirements the larger the number of devices that are compatible.  
  It is important for us that it uses the lowest amount of resources, 
  while not compromising on security and speed.
#### 4. No dependencies, <sub>(unless necessary)</sub>
  Apart from libsodium for cryptographic functions and pthread for thread management, the project relies on the  
  standard C library and custom data structure implementations.
#### 5. Decentralized
  This project, provides a tool not a service. It helps a device send and receive files without needing  
  a central server to coordinate the transaction.

## Current Status: Alpha
**This project is still in development. There is no official release just yet.**
### Complete functionality:
- Device discovery
- Cryptography utilities
- Peer authentication
- Thread creation and management
- Custom data structures **(AVL tree, memory pool, queue, hash tables)**
### In Progress:
- Packet demultiplexing and handling
- File transmission controls
- User interface
  
## Building

Currently there is no official release.  

However, if one wants to compile the project in its current state.  
Usage of CMake is probably the recommended way.  
It is recommended that a MinGW UCRT64 environment is used, as the project relies on pthread for multi threading functionality.  
Also the libsodium library needs to be installed before compilation. 
  
On MSYS2/UCRT64, install libsodium via: 
```
pacman -S mingw-w64-ucrt-x86_64-libsodium
```
## License

[MIT](https://choosealicense.com/licenses/mit/)
