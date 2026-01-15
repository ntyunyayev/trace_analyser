# What is the project about?


This is a small project, that aims to provide a script to analyse the protocol distribution from large traces. It relies on PCAP++.

The tool provides for each protocol, the total number of packets, bytes and connections.

## Prerequisites

- PCAP++
- GFLAG

## Usage

sudo  ./analyser --input_file=<trace.pcap> --output_csv=<output.csv>

