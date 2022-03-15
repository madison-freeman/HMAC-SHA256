   # Stanford University - Cryptography I
  
  ## Week 3 -  Message Integrity and HMAC 
  
  ## Table of Contents

1. [Overview](#overview)
    1. [Problem Statement](#problem)
    2. [Project Motivation](#project-motivation)
2. [Getting Started](#getting-started)
    1. [Data Source](#data-source)
    2. [Dependencies](#dependencies)
3. [Solution](#solution)
4. [Result](#result)
5. [Author](#author)

 ## Overview <a name="overview"></a>
 
 We will use Python to create a program to compute the hash of a given file and to verify blocks of the file as they are received by the client, allowing web browsers to
 authentic files before displaying the content to the user.
 
 ### Problem Statement <a name="problem"></a>
  
 Suppose a web site hosts large video file F that anyone can download. 
 Browsers who download the file need to make sure the file is authentic before displaying the content to the user. 
 One approach is to have the web site hash the contents of F using a collision resistant hash and then distribute the resulting short hash value h = H(F) to users via 
 some authenticated channel (later on we will use digital signatures for this). 
 Browsers would download the entire file F, check that H(F) is equal to the authentic hash value h and if so, display the video to the user. 

 Unfortunately, this means that the video will only begin playing after the *entire* file F has been downloaded. Our goal in this project is to build a file authentication
 system that lets browsers authenticate and play video chunks as they are downloaded without having to wait for
 the entire file. 

 Instead of computing a hash of the entire file, the web site breaks the file into 1KB blocks (1024 bytes). It computes the hash of the last block and appends the value to
 the second to last block. It then computes the hash of this augmented second to last block and appends the resulting hash to the third block from the end. This 
 process continues from the last block to the first as in the following diagram: 
 
 ![SHA256-diagram](https://raw.githubusercontent.com/madison-freeman/HMAC-SHA256/main/SHA256.png)
 
 The final hash value h0 - a hash of the first block with its appended hash - is distributed to users via the authenticated channel as above. 

 Now, a browser downloads the file F one block at a time, where each block includes the appended hash value from the diagram above. 
 When the first block (B0 || h1) is received the browser checks that H(B0 || h1) is equal to h0 and if so it begins playing the first video block. 
 When the second block (B1 || h2) is received the browser checks that H(B1 || h2) is equal to h1 and if so it plays this second block. This process continues until the 
 very last block. This way each block is authenticated and played as it is received and there is no need to wait until the entire file is downloaded. 

 It is not difficult to argue that if the hash function H is collision resistant then an attacker cannot modify any of the video blocks without being detected by the browser. 
 Indeed, since h0 = H(B0 || h1) an attacker cannot find a pair (B`0, h`1) != (B0, h1) such that h0 = H(B0 || h1) since this would break collision resistance of H. 
 Therefore after the first hash check the browser is convinced that both B0 and h1 are authentic.
 Exactly the same argument proves that after the second hash check the browser is convinced that both B1 and h2 are authentic, and so on for the remaining blocks. 

 In this project we will be using SHA256 as the hash function. For an implementation of SHA256 use an existing crypto library such as PyCrypto (Python), Crypto++ (C++), or 
 any other. When appending the hash value to each block, please append it as binary data, that is, as 32 unencoded bytes (which is 256 bits). 
 If the file size is not a multiple of 1KB then the very last block will be shorter than 1KB, but all other blocks will be exactly 1KB. 

Our task is to write code to compute the hash h0 of a given file F and to verify blocks of F as they are received by the client. We seek the (hex encoded) hash h0 for this video file. (https://crypto.stanford.edu/~dabo/onlineCrypto/6.1.intro.mp4_download)

 We can check our code by using it to hash a different file. In particular, the hex encoded h0 for this video (https://crypto.stanford.edu/~dabo/onlineCrypto/6.2.birthday.mp4_download) file is:
 
* 03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8

### Project Motivation <a name="project-motivation"></a>

In the field of digital forensics, a growing problem focuses on defacing and deepfake technologies which are becoming easier to access, and its content easier to create and harder to distinguish from real. Cybercriminals take advantage of these multimedia content manipulation techniques to tamper with original digital photos and videos. Video authentication - a process to establish the fidelity of a digital videos - can combat these digital manipulation tactics. A video authentication system ensures the integrity of digital video, and verifies that the video taken into use has not been doctored. However, video tampering detection remains an open problem in the field of digital media forensics and video tampering techniques are growing at an unprecedented rate. It is more important than ever to detect forgery and ensure proper verification on whether a message or file is authentic before displaying the content to the user. 

## Getting Started  <a name="getting-started"></a>

### Data Source <a name="data-source"></a>
Video image data for in mp4.download file format, downloaded from [Stanford University School of Engineering](https://crypto.stanford.edu/~dabo/).

### Dependencies <a name="dependencies"></a>
* Python 3.*
* Libraries: Crypto, binascii

## Solution <a name="solution"></a>

The cryptographic tool underlying forgery detection is called a hash-based message authentication code. Like an encryption scheme, a hash-based message authentication code consists of three operations: a key generation operation, a hash function operation, and a verification operation.

We assume H to be a cryptographic
   hash function where data is hashed by iterating a basic compression
   function on blocks of data. We denote by B the byte-length of such
   blocks (B = 64 for all the above mentioned examples of hash functions),
   and by L the byte-length of hash outputs (L = 32 for SHA-256). 
   The authentication key K can be of any length up to B, the
   block length of the hash function. Applications that use keys longer
   than B bytes will first hash the key using H and then use the
   resultant L byte string as the actual key to HMAC. In any case, the
   minimal recommended length for K is L bytes (as the hash output
   length).

   We define two fixed and different strings ipad and opad as follows
   (the 'i' and 'o' are mnemonics for inner and outer):

                  ipad = the byte 0x36 repeated B times
                  opad = the byte 0x5C repeated B times.

   To compute HMAC over the data `text' we perform

                    H(K XOR opad, H(K XOR ipad, text))

   Namely,

 * (1) append zeros to the end of K to create a B byte string
        (e.g., if K is of length 20 bytes and B=64, then K will be
         appended with 44 zero bytes 0x00)
 * (2) XOR (bitwise exclusive-OR) the B byte string computed in step
        (1) with ipad
 * (3) append the stream of data 'text' to the B byte string resulting
        from step (2)
 * (4) apply H to the stream generated in step (3)
 * (5) XOR (bitwise exclusive-OR) the B byte string computed in
        step (1) with opad
 * (6) append the H result from step (4) to the B byte string
        resulting from step (5)
 * (7) apply H to the stream generated in step (6) and output
        the result
        
## Result <a name="result"></a>

* 5b96aece304a1422224f9a41b228416028f9ba26b0d1058f400200f06a589949

 
## Author<a name="author"></a>
* [Madison F.](https://github.com/madison-freeman)
