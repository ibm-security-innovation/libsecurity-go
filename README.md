# libsecurity-go
## Overview:
### The goals of libsecurity are:
Secure "things" that connect to the internet by providing a set of security libraries/services that fulfill the following requirements:
1.  Complete (from a security point of view)
2.  Can be easily integrated with existing IoTs' software.
3.  Optimized for the IoTs' run time environment

### Out of scope
- Denial of service - this mainly refers to applicative implementation related weaknesses (like a poor hash function) which are beyond our reach
- Physical attacks

### Language
- Implemented in Go
- [REST API](./swagger-dist/index.html)

## Provided Libraries:
  - Initialization services including a utility that generates an initial secureStorage file to be used later by all other components
  - Token services for allowing transfer of users' information between client and server using secure JSON Web Token (JWT) cookies.
  - Account Management services:  User privileges and password management
  - Secure storage services: Persistency mechanism that uses Encryption (AES) of key-value pairs within a signed file
  - Entity management services to handle 3 types of entities: User, Group and Resource.
  - Password services:  encryption, salting, reset, time expiration, Throttling mechanism
  - OATH services: OCRA as defined by RFC 6287
  - Authentication services as defined by OpenID connect
  - Authorization services as defined by OAUTH 2.0
  - Access Control List (ACL) services when access rights may be defined for resource entity. The  implementation should allow flexible types of access to resources (not limited to READ/WRITE/EXECUTE).
  - One Time Password (OTP) services as defined by RFCs 4226 (HOTP), 6238 (TOTP)

## Higher layers:
- RESTful layer: most of the above libraries have a RESTful layer
- Examples:
  1. Each of the above libraries have usage examples
  2. All the above libraries are combined into libsecurity-go RESTful GUI (each library could be shown/hidden using the tool configuration file)

## Installation
### Prerequisites
- Installed Go environment

### Quick Start
- Under the $GOPATH, create the following directory (if does not exist yet): src, pkg, bin
- Under the src directory, create the following path: ibm-security-innovation/libsecurity-go
- **cd ibm-security-innovation/libsecurity-go**
- Clone the library with **git clone https://github.com/ibm-security-innovation/libsecurity-go .**
- Copy all the needed external libraries using go get
  - e.g.
    - **cd libsecurity-go/entity**
    - **go get**
- Running a RESTful GUI example:
  - When entering for the first time, the following steps should be executed:
  1. Generate an RSA file (you can generate it also when generating the basic secure storage, see item 3) by running:
    - **ssh-keygen** (This will result with the following prompts filled with the user chosen values)
      - **Generating public/private rsa key pair.**
      - **Enter file in which to save the key (~/.ssh/id_rsa): ./dist/test.rsa**
      - **Enter passphrase (empty for no passphrase):**
      - **Enter same passphrase again:**
      - **Your identification has been saved in ./dist/test.rsa**
      - **Your public key has been saved in ./dist/test.rsa.pub**
  2. Create a secureKey file in the ./dist directory. The secureKey file should contain a strong password to be used for encryption of the setup storage file. It is recommended that the password will be based on a random value  which is at least 16 bytes long. Note that some additional manipulation will be done for further strengthening the initial password before it is used.
  3. Generate a minimal secure storage (a file that contains just the root user with its privilege and password) and RSA files by executing the following steps:
      - **cd setup**
      - **go run setup_storage_.go**
        -storage-file="./dist/data.txt" -password="your new compliant
      password here" -secure-key="./dist/secureKey" -generate-rsa=true
      - **cd ..**
Note: if you generated the RSA files, copy them to the dist directory (the generated RSA files are: key.private and key.public)
- The following should be done any time the RESTful API browser is used:
  - Running the RESTful server
    - change directory to the restful/libsecurity directory
    - **go run libsecurity.go**
    -  -config-file (default "./config.json"): Configuration information file
    -  -host (default "localhost:8080"): Listening host
    -  -protocol (default "https"): Using protocol: http ot https
    -  -rsa-private (default "./dist/key.private"): RSA private key file path
    -  -secure-key (default "./dist/secureKey"): password to encrypt the secure storage
    -  -server-cert (default "./dist/server.crt"): SSL server certificate file path for https
    -  -server-key (default "./dist/server.key"): SSL server key file path for https
    -  -storage-file (default "./dist/data.txt"): persistence storage file
  - In the browser address bar type: **https://ip:port/forewind/doc** (or **http://ip:port/forewind/doc**) (The default is: https://127.0.0.1:8080/forewind/doc)
    - click on the **/forewind/app/v1/accounts-manager**
    - click on the **/forewind/app/v1/account-manager/user** link in order to authenticate the user
    - After filling the user name and password, click on the **Try it out** button.
      - If the account information is correct the "Response body" should contain the line **"Match" : true**.
    - Click on the directory link in order to Change/Update/Save the relevant data using the RESTful API

### License

(c) Copyright IBM Corp. 2010, 2015
This project is licensed under the Apache License 2.0. See the LICENSE file for more info.

- 3rd party software used by libsecurity-go
  - jwt-go, https://github.com/dgrijalva/jwt-go , MIT
  - swagger, https://github.com/swagger-api , Apache v2
  - go-restful https://github.com/emicklei/go-restful,  MIT
  - marked  https://github.com/chjj/marked , MIT

# libsecurity-go architecture and high level design document
## Overview:
The purpose of libsecurity-go is to provide an efficient solution for securing Internet Of Things end devices and gateways. This solution does not require any deep understanding of security and thus relieves IoT developers from the need to learn and understand the different aspects of security (e.g. how to create and maintain secure-storage, when to use One Time Password etc.).

Libsecurity-go implementations targeted to Linux capable IoT platforms (e.g. ARM Cortex A). This implementation includes two additional layers: a RESTful layer and an Application layers.

| __________ | ___________ | Architecture Layers | ____________ | _______________________________ |
| ---------- | ----------- | :------------------:| ------------ | ----------------------------- |
| | | Application Layer | | |
| | | Rrestful API | | |
| | | Account Management + Meta Data | | |
| Access Control List | Password (with salt) | One Time Password | OAuth OCRA | |
| | | Entity Manager | | |
| | | Secure Storage | | |
| | | Encryption | | |

## Architecture and High level design:
The following diagram details the layers of libsecurity :

- The encryption layer is the lowest one (where either Go encryption or NaCl encryption library are used).
- The second layer, Secure Storage, implements secure storage for persistency. The secure storage is based on encrypted key value pairs stored in signed files to guarantee that the data is not altered or corrupted (more details will be presented later)
- The next layers are designed as entity centric, where entities must have a name and may have a list of associated properties and a list of members (see more details and example below)

### Possible associated properties:
- Account Management: the entity's privilege (Super user, Admin or User), password related information and handling methods including  current password, old passwords list, salt, whether it is a 'one time password' (after password reset), and password expiration time.
- Password handling (for cases when password mechanism other than the Account management is required). This may include: current password, old passwords list, salt, whether it is a 'one time password' (after password reset), password expiration time, whether the password is locked and more.
- Access control List (ACL): Permissions associated with the resource entity. Permissions are defined as a string to provide flexibility (in contrast with the old Read/Write/Execute model). The string may have any legal string value (e.g. "Can take", "can play")
    - Note: We chose to implement only a positive mechanism - listing what is allowed. We believe that this is more intuitive and easy to manage compared with a combination of positive assertions with negative ones. More details and examples below

### Library structure:
- Each package includes the code, documentation and a usage example
- Linux capable systems:
    - RESTful API layer: Each of the components has its own RESTful layer providing interface with external calls (Built GUI interface to the RESTful API using Swagger)
Application Layer: A set of “glue components” to ease the use of the security tool (e.g. addition of an ACL permission description)

### Major Data and Property Structures:
#### Secure Storage
    - Allows maintaining data persistently and securely. The implementation of the secure storage is based on encrypted key value pairs stored in signed files to guarantee that the data is not altered or corrupted.
    - Both the key and the value are encrypted when added to the storage using an Advanced Encryption Standard (AES) algorithm.
    - Each time a new secure storage is generated, a secret supplied by the user accompanies it and is used in all HMAC and AES calculations related to that storage .
In order to make it difficult for a third party to decipher or use the stored data we ensure that multiple independent encryptions of the same data (e.g. a block with the same piece of plain text) with the same key have different results. This is achieved by implementing the Cipher Block Chaining (CBC) mode.
    - In order to implement a time efficient secure storage with keys (i.e. identify keys that are already stored without decrypting the entire storage, and when such a key is identified replacing its value) a two step mechanism is used. The first time a key is introduced, a new IV is drawn, the key is 'HMAC'ed with the secret and is stored with the IV as the value (1st step). Than the original key is encrypted with the drawn IV and stored again, this time with the (encrypted with its own random IV) value (2nd step).  The next time that same key is stored, the algorithm, identifies that it already exists in the storage, pulls out the random IV (stored in the 1st step), finds the 2nd step storage of that key and replaces its value with the new (encrypted) one.
    - In order to guarantee that the data is not altered or corrupted the storage is signed using HMAC. The signature is added to the secure storage, when the storage is loaded, HMAC is calculated and compared with the stored signature to verify that the file is genuine.

- Entity structure:
    - There are three types of entities: User, Group and resource
        - Users have a name and a list of properties
        - Groups have a name, list of members associated with it (each member is a name of an existing entity) and a list of properties
        - Resources have a name and a list of properties
        - There is a special group entity, that is not defined explicitly, with the name "All". This entity is used in the ACL when the resource has permission properties that applies to all the entities in the system

- Properties:
    - ACL property structure:
        - An ACL has a list of entries. Each ACL entry consists of the following fields:
            - An entry name (obligatory, must be the name of an entity from the entity list)
            - List of permissions (optional)

        - Example:
            - Consider the following entity list:
                - Name: User1
                - Name: User2
                - Name: User3
                - Name: IBM, members: User2, User3
                - Name: All (reserved token)
                - Name: Disk, properties: ACL:
                - ACL →
                    - Name: User1, properties: “can write”, “can take”
                    - Name: IBM, properties: “can read”
                    - Name: All, Properties: “can execute”
            - In this example:
            1. The user-entity named User1 has the following permissions with relation to the resource-entity Disk: “can write”, “can take” and “can execute” (via All)
            2. The group-entity named IBM has the following permissions with relation to the resource-entity Disk: “can read” and “can execute” (via All)
            3. The user-entity named User2 has the following permissions with relation to the resource-entity Disk: “can read” (via IBM) and “can execute” (via All)

            - Note: if User1 is removed from the Entity list and then re added, the only permission it will initially have is “execute” (via All). This is because a removed entity cannot be re-added, but a new entity with its name can be created. In this case, the new Entity User1 may be of a different user than the one that originally received the permissions.

    - The OTP property:
        - According to Wikipedia: A One Time Password (OTP) is a password that is valid for only one login session or transaction (and may be limited for a specific time period). The most important advantage that is addressed by OTPs is that, in contrast to static passwords, they are not vulnerable to replay attacks. A second major advantage is that a user who uses the same (or similar) password for multiple systems, is not made vulnerable on all of them, if the password for one of these is gained by an attacker.
Libsecurity implements the 2 possible OTP implementations: A time based one time password algorithm (TOTP) and HMAC-based one time password algorithm (HOTP). Our OTP implementation is based on RFC 2289 for OTP in general, RFC 4226 for HOTP, and RFC 6238 for TOTP.
        - The OTP implementation has three layers:
            - The base layer includes the secret, the digest (e.g. SHA256, SHA1) and the number of digits in the result.
            - The second layer is the counting mechanism which is time based for TOTP and counter based for HOTP.
            - The topmost layer includes the policy of handing unsuccessful authentication attempts. This includes blocking and throttling. The blocking mechanism allows blocking users for a given duration (or until a manual unblock) after they pass a threshold which a limit for the number of allowed consecutive unsuccessful authentication attempts. The throttling mechanism controls the delay between the authentication request and the response. This delay is increased as the number of consecutive unsuccessful attempts grows to avoid brute force password attacks. This layer also includes a time window for avoiding clock drifting errors when TOTPs are used.

    - The OCRA property:
        - According to Wikipedia: Challenge–response authentication: is a family of protocols in which one party presents a question ("challenge") and another party must provide a valid answer ("response") to be authenticated. It may be used for mutual authentication e.g. when a server needs to install a new version on a client. In the case of the example, the client has to verify that the server is the one it claims it is (otherwise a  malicious version may be downloaded) and the server has to verify that it sends the new version to the right client.
