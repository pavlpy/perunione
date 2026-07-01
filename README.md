# perunione ⚡️

A custom, paranoid, lightweight 1024-bit asymmetric cryptographic protocol and peer-to-peer transport suite written in pure C. Works good in Linux user-space(tested on Arch Linux). 

The name bridges **Perun** (the ancient Slavic deity of thunder and absolute lightning-fast force) .

---

## 🧬 Inside the Armor (How it works)

`perunione` is relying only on standard C library (`stdlib`). It is designed from scratch with performance and extreme security in mind:

1. **Custom 1024-bit Elliptic Curve**: Built over a massive Pseudo-Mersenne prime field $P = 2^{1024} - 105$. Fully custom base point $G$ coordinates. Resistant to future quantum attacks.
2. **Binary Extended GCD**: 1024-bit modular inverse calculated without heavy division, using only fast bitwise shifts and subtractions.
3. **Pseudo-Mersenne Reduction**: Multiplication is optimized via folding the high 1024-bit half into the low half using $2^{1024} \equiv 105 \pmod P$, bypassing standard slow division.
4. **Paranoid Cascaded Encryption**: 
   * REP constant determines how much times the encryption repeats. The default is 7.
   * The encrypt cycle contains:
        * S-Box
        * Byte Rotation
        * XOR with key
        * After it, 1024-bit shared secret is sliced into four 256-bit keys, and data is being encrypted with all four keys.
5. **Perfect Forward Secrecy**: Automatic key rotation and re-handshake triggers safely before session boundaries to completely mitigate Timing Attacks.

---

## 🛠️ Compilation

Compiled with pure GCC and `-O2` flag for maximum hardware optimization:

```bash
make
```

## 📜 License

This project is open-source and licensed under the **GNU General Public License v3.0 (GPLv3)**. 

In the spirit of Richard Stallman and true digital freedom, if you modify or use `perunione` in your own software, **you are strictly obligated to open-source your entire project**. Keep the code free, keep the crypto strong. 

Feel free to audit, or use it to hide from global surveillance.


## ⚠️ Important Security Notes & Constraints

### 1. Transport & Addressing Layer Abstraction
`perunione` is strictly a cryptographic state engine and data stream chunker. **It does not handle network routing, peer addressing, or packet delivery guarantees.** 
* It is the developer's absolute responsibility to wrap the exported 1 KB raw `Packet` structures into UDP/IP, raw Ethernet frames, or your custom transport layer.

## 📖 Documentation & Integration

To see the detailed function reference, understand the architecture, and look at practical code snippets on how to use this library, see [using.md](using.md).

