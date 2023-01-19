# plonky2-zkedit
Using plonky2 to prove the transformations over attested images

### About
This project goal is to make image transformations authentication secure and practical. The main features that help achieve it are as follows:
 1. Using [plonky2](https://github.com/mir-protocol/plonky2) and it's highly optimized Poseidon gates.
 2. Describing and implementing the algorithm of chunked proving.
 3. Swapping the hash algorithm from default SHA-256 to ZK-friendly one - _Poseidon_

### Current state
The project is in development. Currently, it can prove and verify the crop operation of the arbitrary png images in fast time.

The benchmark of proving the Crop operation for various-sized images can be seen bellow.
| Resolution             | 256×256 | 700×700 | 1520×934 | 2048×1080 |
|------------------------|:-------:|:-------:|:--------:|:---------:|
| File size              |  256 KB | 1.86 MB |  5.41 МB |  8.43 МB  |
| Circuit build, seconds |    2    |    12   |    32    |     36    |
| Prover time, seconds   |    3    |    16   |    37    |     54    |
| Verifier time, seconds |   <0.1  |   <0.1  |   <0.1   |    <0.2   |
| RAM consumption        | ~480 MB | ~5.1 GB |  ~6.2 GB |  ~9.3 GB  |
| Prove size             |  130 KB |  132 KB |  133 КB  |   135 KB  |

### Proving
```bash
cargo run --release -- prove -i <orig-img-path>
```

These will create the file metadata.json, which will contain the compressed proof in binary and some other data.

### Verifying
```bash
cargo run --release -- verify -e <edited-image-path> -m <metadata-path>
```

### Contacts
Feel free to reach out if you have any questions or want to contribute.

 - [Twitter](https://twitter.com/roman_palkin)
