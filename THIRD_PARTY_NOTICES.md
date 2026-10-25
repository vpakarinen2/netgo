# Third-party notices

## Wasm runtime

Netgo embeds [wazero v1.12.0](https://github.com/tetratelabs/wazero), licensed
under the Apache License 2.0. A copy of that license is included in `LICENSE`.
The upstream NOTICE is reproduced here:

```text
wazero
Copyright 2020-2023 wazero authors
```

## Common TCP port lists

The 100- and 1,000-port presets in `pkg/network/targets/topports.go` are adapted
from [ProjectDiscovery Naabu](https://github.com/projectdiscovery/naabu/blob/5a0ca8bde91b5bb16213e9e8b5c6871eac954bd8/pkg/runner/ports.go).
The upstream lists are named `NmapTop100` and `NmapTop1000`. These are fixed
common-port sets, not measurements of current traffic. Netgo's 10-port preset
is a quick selection from the same sets. No Naabu runtime dependency is added.

The following license applies to the adapted lists:

MIT License

Copyright (c) 2021 ProjectDiscovery, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
