## Welcome to Free Enc

**Intro**

Small CLI rust program implementing AES-256-CBC w/ PBKDF2 for Key Derivation. I was building something similar w/ .NET Core to try out new features but then building it in rust sounded fun and I've wanted to get better at rust for awhile. Anyway, since I'm still learning rust I'm sure there is plenty of room for improvement and with that there may be bugs in this program and it has not been audited, use at your own risk! I do plan on maintaining the repo for while along with adding new features so please submit an issue for anything you would like to see done.

**Building and running locally**

1. Install Rust Tools(rustup): https://rust-lang.org/learn/get-started
2. Clone this repo locally 
3. Build and run the program locally w/ Cargo: https://doc.rust-lang.org/cargo/index.html

**Notes** 

- The Salt and IV are prepended to the cipertext when saved, separated by a "===". 
- This program is in it's early stages of development, you may encounter bugs, if you are using this program on anything of importance consider other, well tested, encryption tools. If you do use this program please make temp files before encryption and decryption in-case of a fatal crash.
