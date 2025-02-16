# Nprint-rs
Rust adaptation of [nprint](https://nprint.github.io/)

## Roadmap
### Development
- First working parsing ✔ 
- Structures to handle different packets/mbuf/\[u8\]/vec\[u8\]
- Convert PCAP to nprint
- Parsing a set of packets per connection (1/2/5/10/20/...)
- Parse protocols:
  - IPv4 ✔ 
  - TCP ✔ 
  - Ethernet
  - IPv6
  - UDP ✔ 
  - QUIC
  - ICMP
  - Payload
 
### Miscellaneous
- Better Readme
- Documentation
- Setup test github actions ✔ 

## How to contribute
If you have any doubts or need additional information, don't hesitate to ask for more information in the comments section.

### Step by step
- Assign yourself to an issue
- Create a branch
- Write unit tests
- Fix the issue 
- Make sure your code passes the CI's tests
- Create a PR 
### Run tests
Your code must pass:
```
cargo fmt --check && cargo clippy --all && cargo test --all && cargo build
```
