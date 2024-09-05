# Bike-Scan - a scanning tool to scan ipsec server

## Purpose of this project
The purpose of this project is to scan ipsec servers reliably.
Bike-Scan finds all transformations of a server if it is configured with the IkeV1 protocol.
In the case of a configuration with the IkeV2 protocol, the first transformation in the configured list is found but only if the Diffie-Hellman group of the Key Exchange Payload is 1024-Bit modp.
Bike-Scan was developed as part of a bachelor thesis in collaboration with Trufflepig IT-Forensics GmbH.

## Tutorial (Linux)

## Prerequisites (if needed):
1. Download and install Rust (using rustup is recommended) on www.rust-lang.org/tools/install
2. Download and install cargo via package manager (e.g. sudo apt install cargo)
3. Download git via package manager (e.g. sudo apt install git)

## Download and Install:
1. git clone this repository in desired location
```
git clone https://github.com/trufflebee33/bike-scan.git
```
2. cd into cloned bike-scan folder
3. install using cargo
```
cargo install --path .
```

## HOW TO USE
Currently only scans for IKE Version 1 are avaiable
```
cargo run -- v1 <ip>
```
