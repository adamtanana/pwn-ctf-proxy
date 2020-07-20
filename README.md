TODO(adam): add a proper readme

A CTF proxy for pwn challenges that want unique FLAGS per challenge, user. Also logs all messages sent to the server in a format traceable back to an individual session stored in a flag.

Proxy runs via a config, and individual challenges only need to support having a flag that is of a specific format, which will be replaced inline by the proxy.

## Usage:

All code lives in `tanana/`.
Build system used is bazel with -std=c++17, run with:

#### To run ctf-proxy
```
bazel run //tanana/ctf-proxy -- "SOME SECRET KEY" config.json
```

where config.json is like
```
[
    {
        "chal": "war5-shellcrack",
        "lhost": "0.0.0.0",
        "lport": 5001,
        "rhost": "172.20.0.17",
        "rport": 9999
    },
    {
        "chal": "war5-stack-dump2",
        "lhost": "0.0.0.0",
        "lport": 5002,
        "rhost": "172.20.0.18",
        "rport": 9999
    },
    {
        "chal": "war5-image-viewer",
        "lhost": "0.0.0.0",
        "lport": 5003,
        "rhost": "172.20.0.29",
        "rport": 9999
    }
]
```

Each challenge should have a flag where the flag is of the format.
```
FLAG{sha256sum(chalname))}
```

I have a folder of `war5/shellcrack`, `war5/stack-dump2`, etc.. And I use the command
```
printf "FLAG{%s}\n" $(echo -n "${folder}-${chal}" | sha256sum | cut -d' ' -f1)
```

to generate valid flags.

#### To check flags
```
bazel run //tanana/flag-checker -- "SOME SECRET KEY" cheater|marker
```

Then pass in a list of `userid flag` such as:
```
z1234567 FLAG{xxX}
z1234568 FLAG{yyy}
```

## credits:

> json
This is a modified version of http://github.com/nlohmann/json

> jwt
This is a modified version of https://github.com/Thalhammer/jwt-cpp.

these libraries are not my code
