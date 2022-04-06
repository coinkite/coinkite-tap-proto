# cktap
List of cktap commands with examples (WIP)

## core

```shell
% cktap core -p  # this will dump all used slots as watch only (no CVC provided)
Warning: Without the code, can only watch addresses from this card.

importdescriptors '[
  {
    "desc": "addr(tb1qdu05evh9kw0w482lfl2ktxm6ylp060kmqpe5js)#n0s7nyz0",
    "timestamp": 1648215566,
    "internal": false,
    "label": "slot_0"
  },
  {
    "desc": "addr(tb1qf0p2rky4d9knwdxz4pqnxv68j3cr0dyp6yp3h0)#6de55q4e",
    "timestamp": 1648215566,
    "internal": false,
    "label": "slot_1"
  },
  {
    "desc": "addr(tb1q6tjz70fyh4c3l2muk4fexfvpuq39p3657sxquy)#etka7xuj",
    "timestamp": 1648215566,
    "internal": false,
    "label": "slot_2"
  },
  {
    "desc": "addr(tb1q7wz86pgrswqzsnc4u7qt0zu7zjrqgjqr5q7lh5)#9c8u3mjt",
    "timestamp": 1648215566,
    "internal": false,
    "label": "slot_3"
  }
]'

% cktap core 123456 -p  # this will dump only unsealed slots (CVC provided)
importdescriptors '[
  {
    "desc": "wpkh(cU7CGBhwnMdLDbqBaXm3xE22KFyaA5s3YDBis88LyuPLnmfpDFFU)#2kyyxsrc",
    "timestamp": 1648215566,
    "internal": false,
    "label": "slot_0"
  },
  {
    "desc": "wpkh(cTUoyVV4m9FZJXW9CBMRKbKa1UQ4BiUy49i5v7Q5KJkZ9dv1h7Kw)#cf3asx2t",
    "timestamp": 1648215566,
    "internal": false,
    "label": "slot_1"
  },
  {
    "desc": "wpkh(cMvFqzkcfibpt4WJuuHWq6SpKLZmxWFQCD5hxtSGdRzdcbVKafQz)#7vp0t4rx",
    "timestamp": 1648215566,
    "internal": false,
    "label": "slot_2"
  }
]'

% cktap core 123456 -s 0 -p  # dump only slot 0 (with CVC with private key)
importdescriptors '[
  {
    "desc": "wpkh(cU7CGBhwnMdLDbqBaXm3xE22KFyaA5s3YDBis88LyuPLnmfpDFFU)#2kyyxsrc",
    "timestamp": 1648215566,
    "internal": false,
    "label": "slot_0"
  }
]'

% cktap core -s 0 -s 2 -p  # dump only slot 0 and slot 2 watch only (no CVC provided)
Warning: Without the code, can only watch addresses from this card.

importdescriptors '[
  {
    "desc": "addr(tb1qdu05evh9kw0w482lfl2ktxm6ylp060kmqpe5js)#n0s7nyz0",
    "timestamp": 1648215566,
    "internal": false,
    "label": "slot_0"
  },
  {
    "desc": "addr(tb1q6tjz70fyh4c3l2muk4fexfvpuq39p3657sxquy)#etka7xuj",
    "timestamp": 1648215566,
    "internal": false,
    "label": "slot_2"
  }
]'

```