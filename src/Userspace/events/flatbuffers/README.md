# owLSM FlatBuffers

## Version
- **FlatBuffers**: v25.12.19
- **flatc compiler**: v25.12.19 (clang++-18 build)

## Directory Layout
```
flatbuffers/
├── README.md           # This file
├── schema/
│   └── owlsm_events.fbs       # Source-of-truth schema
└── include/
    └── owlsm_events_generated.h  # Auto-generated C++ header
```

## Regenerating Headers, use script
```bash
scripts/flatbuffers_compile.sh
```

## Wire Format
Each message is a **size-prefixed FlatBuffer**: a 4-byte little-endian `uint32` length followed by that many bytes of FlatBuffer data.
```
┌─────────────────────┬────────────────────┐┌─────────────────────┬────────────────────┐
│ 4 bytes prefix      │      N bytes       ││ 4 bytes prefix      │      M bytes       │
│ indicating message  │ FlatBuffer payload ││ indicating message  │ FlatBuffer payload │
│ size. Size N        |                    |│ size. Size M        |                    |
└─────────────────────┴────────────────────┘└─────────────────────┴────────────────────┘
```

### Reader Pseudocode
```
while not EOF:
    size = read_uint32_le(stream)
    buf  = read_exactly(stream, size)
    msg  = GetSizePrefixedRoot<Event|Error>(buf)
```
