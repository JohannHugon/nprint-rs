# Nprint-rs

Rust library that adapt [nprint](https://nprint.github.io/) in Rust.

## Why
nPrint is a standard data representation for network traffic, designed for direct use with machine learning algorithms, eliminating the need for feature engineering in various traffic analysis tasks. Developing a Rust implementation of nPrint will simplify the creation of network systems that leverage real-world ML deployments, rather than just training and deploying models offline.

## Documentation
### Installation 
To use Nprint-rs in your project, add the following to your Cargo.toml:
```
[dependencies]
nprint-rs = "*"
```
Or simply by executing: 
```
cargo add nprint-rs
```
### Usage
Documentation https://docs.rs/TBD/

## Roadmap
This is an open roadmap, if you want to request or update something don't hesitate to open an issue and then we'll talk about it.
More information on how to do it in [CONTRIBUTING](CONTRIBUTING.md)

### Features
- First working parsing ✔ 
- Structures to handle different packets/mbuf/\[u8\]/vec\[u8\]
- Convert PCAP to nprint
- Parse a set of packets per connection (1/2/5/10/20/...) ✔ 
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
- Better Readme ✔ 
- Documentation ✔ 
- Set up test github actions ✔ 

## How to contribute
If you have any doubts or need additional information, don't hesitate to ask for more information in the comments section of an issue.
Go to [CONTRIBUTING](CONTRIBUTING.md)


