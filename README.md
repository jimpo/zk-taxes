# Zero-knowledge Income-Taxed Transactions

This library implements basic transaction construction and validation rules for a ZCash-like
cryptocurrency ledger supporting flexible income tax schemes. See paper for details on the ledger.

## Status

This is academic quality, extremely under-tested, certainly contains bugs, should not be used in
production, value-bearing applications, yadda yadda yadda.

## Running tests and benchmarks

You must have Rust stable installed using rustup. Most commands should be run with `--release` as
some cryptographic operations run extremely slowly in debug mode.

First, generate the common reference string for all zk-SNARK proofs by running:

```bash
$ cargo run --bin generate_params --release
```

Run the tests with

```bash
$ cargo test --release
```

Run the benchmarks with 

```bash
$ cargo bench
```

## License

Copyright 2019 Jim Posen

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

