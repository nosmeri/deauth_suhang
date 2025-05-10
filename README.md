# Deauth Tool

## Table of Contents

- [About](#about)
- [Getting Started](#getting_started)
- [Usage](#usage)

## About <a name = "about"></a>

This is made for python information assignment.

This project is based on the Ubuntu environment.

## Getting Started <a name = "getting_started"></a>

### Requirements

For building and running the application you need:

+ [Aircrack-ng](https://www.aircrack-ng.org/)
+ Lancard with monitor mode

### Installation

    $ git clone https://github.com/nosmeri/deauth_suhang.git
    $ cd ./deauth_suhang
    $ sudo pip install -r ./requirements.txt
    $ sudo python3 ./main.py

## Usage <a name = "usage"></a>

1. enter your interface.
2. switch to monitor mode.
3. scan AP.
4. select the AP you want to attack.
5. enter the number of packets to send.
6. attack!