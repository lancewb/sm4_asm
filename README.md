# SM4 Encryption Implementation in Go

This repository provides a Go implementation of the SM4 block cipher, a Chinese national standard for wireless networks. It includes support for various modes of operation, including ECB, CBC, CFB, OFB, and GCM. The implementation is designed to be straightforward and easy to use in your Go projects.

## Features

- **SM4 Block Cipher**: A complete implementation of the SM4 algorithm.
- **Multiple Modes of Operation**:
    - Electronic Codebook (ECB)
    - Cipher Block Chaining (CBC)
    - Cipher Feedback (CFB)
    - Output Feedback (OFB)
    - Galois/Counter Mode (GCM) for authenticated encryption.
- **PEM Key Handling**: Utilities for reading and writing PEM-encoded SM4 keys, with optional password-based encryption.
- **Incomplete Assembly Acceleration**: An incomplete assembly-accelerated version for performance-critical applications (falls back to the pure Go implementation if the required CPU features are not available).

## Installation

To use this library in your Go project, you can use `go get`:

```bash
go get github.com/your-username/sm4_asm
```

## Usage

Here are some examples of how to use the library for encryption and decryption.

### Basic Encryption and Decryption (ECB Mode)

```go
package main

import (
	"fmt"
	"github.com/your-username/sm4_asm"
)

func main() {
	key := []byte("1234567890abcdef")
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}

	// Encrypt
	ecbMsg, err := sm4.Sm4Ecb(key, data, true)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Encrypted (ECB): %x\n", ecbMsg)

	// Decrypt
	decrypted, err := sm4.Sm4Ecb(key, ecbMsg, false)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Decrypted (ECB): %x\n", decrypted)
}
```

### CBC Mode

```go
package main

import (
	"fmt"
	"github.com/your-username/sm4_asm"
)

func main() {
	key := []byte("1234567890abcdef")
	iv := []byte("0000000000000000")
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}

	sm4.SetIV(iv)

	// Encrypt
	cbcMsg, err := sm4.Sm4Cbc(key, data, true)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Encrypted (CBC): %x\n", cbcMsg)

	// Decrypt
	decrypted, err := sm4.Sm4Cbc(key, cbcMsg, false)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Decrypted (CBC): %x\n", decrypted)
}
```

### GCM Mode (Authenticated Encryption)

```go
package main

import (
	"bytes"
	"fmt"
	"github.com/your-username/sm4_asm"
)

func main() {
	key := []byte("1234567890abcdef")
	iv := make([]byte, sm4.BlockSize)
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	additionalData := []byte("additional authenticated data")

	// Encrypt
	ciphertext, tag, err := sm4.Sm4GCM(key, iv, data, additionalData, true)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Ciphertext (GCM): %x\n", ciphertext)
	fmt.Printf("Tag (GCM): %x\n", tag)

	// Decrypt and verify
	plaintext, newTag, err := sm4.Sm4GCM(key, iv, ciphertext, additionalData, false)
	if err != nil {
		panic(err)
	}

	if bytes.Equal(tag, newTag) {
		fmt.Println("Authentication successful!")
		fmt.Printf("Plaintext (GCM): %x\n", plaintext)
	} else {
		fmt.Println("Authentication failed!")
	}
}
```

### PEM Key Handling

You can also read and write SM4 keys from and to PEM files.

```go
package main

import (
	"fmt"
	"github.com/your-username/sm4_asm"
)

func main() {
	key := []byte("1234567890abcdef")
	password := []byte("my-secret-password")

	// Write key to a PEM file (with encryption)
	err := sm4.WriteKeyToPemFile("key.pem", key, password)
	if err != nil {
		panic(err)
	}

	// Read key from the PEM file
	readKey, err := sm4.ReadKeyFromPemFile("key.pem", password)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Read key: %s\n", string(readKey))
}
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
