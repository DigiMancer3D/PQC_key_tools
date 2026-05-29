# PQC Tools (Basic Versions)

These are original simple C programs that create and use post-quantum keys using custom seeding.

## 1. pqc_keygen.c, How the basic keychain is built

This program makes one `.kchain` file with master keys plus 9 role keys.

### Step-by-Step

1. **Start seed**  
   64 random bytes become 512 trits:  
   `trits[i] = '0' + (random_byte[i % 64] % 3)`  
   (Each trit is 0, 1 or 2.)

2. **Expand**  
   Loop the binary into trits until longer than 10,000 trits using:  
   - `ternary_d_shift`:  
     ```
     result[0] = trits[0]
     for i = 1 to end:
         if previous trit == next trit → '0'
         else if previous > next → '1'
         else → '2'
     ```  
   - `full_pass(current, previous)`:  
     Split string into three parts A B C (each length/3).  
     Shift each → newA, newB, newC.  
     `jump[i] = ((a XOR b) + (c XOR b)) % 3`  
     Mix with XOR on original, add previous round mod 3, then clean.  
   - **SPX-QEC cleanup** (up to 20 rounds):  
     Remove every occurrence of these exact strings (and their built versions):  
     `"00"`, `"11"`, `"01"`, `"10"`, `"100"`, `"011"`, `"101"`, `"010"`, `"1001"`, `"0110"`, `"10100"`, `"01011"`, `"001101"`.  
     (It repeatedly searches and deletes them like a simple error filter.)

3. **Reduce to exactly 6000 trits**  
   Run `ternary_d_shift` 8 times.  
   Then fold:  
   `folded[i] = ((trit[(i*17) % len] XOR trit[(i*17 + len/3) % len]) % 3)`

4. **Master entropy**  
   SHAKE-256 on the 6000 trits → 512-byte pool.  
   All keys pull random numbers from this pool only.

5. **Create keys**  
   - Master: Falcon-512, ML-DSA-65 (called Dilithium3), SLH-DSA-SHA2-128s (SPHINCS+).  
   - Roles 0–8: same three algorithms each.  
   Everything saved as hex strings inside clean JSON.

**What you see when you run it**  
Progress lines like:  
`[1/7] Generating high-entropy 512-trit seed... Generated 512 ternary digits`  
`[2/7] Expanding to 10k+ trits with SPX-QEC...`  
`✅ Keychain saved to: ../svc-wallet/pqc_master_2026....kchain`  

**Quick check**  
After generation you can run either validation program on the new `.kchain` file. The key validator loads the JSON, pick master and some role keys, do a real sign + verify test for Falcon-512 and SPHINCS+ (or Dilithium), and print PASS or any error. The kchain validator does less intensive checks.

## 2. pqc_hybrid_signer_old.c, How basic hybrid signing works

Run example:  
`./pqc_hybrid_signer_old myfile.kchain 4 "Hello this is a test"`

### Siginig Process

1. **Load**  
   Opens `.kchain`, finds role 4, reads its SPHINCS+ secret key (and optional btc styled keys).

2. **Bitcoin part**  
   Signs the raw message with secp256k1 ECDSA (standard OpenSSL call, returns DER format).

3. **PQC part (the wrapper)**  
   - Compute `state = SHA3-256(BTC_signature + original_message)` (128 bytes).  
   - Turn into 512 trits: `trits[i] = '0' + (state[i % 64] % 3)`.  
   - Run exact same SPX-QEC cleanup (delete the 13 patterns up to 20 times).  
   - Call standard PQC signing:  
     `OQS_SIG_sign("SLH_DSA_PURE_SHA2_128S", signature, &len, state, 128, secret_key)`  
     *(A normal pure PQC signer would simply do `OQS_SIG_sign(..., original_message, message_length, ...)` with no BTC step and no trit cleaning.)*

4. **Combine**  
   Blob = BTC_sig + SPHINCS+_sig + 32 zeroed padding bytes (`0xAA`).  
   Base58-encode the whole blob → long printable “faux signature”.

**What you see**  
```
✅ Hybrid SPHINCS+BTC Signature (faux base58 - looks exactly like a normal Bitcoin signature):
[long base58 string here]

Inner BTC ECDSA part is fully verifiable...
Outer SPHINCS+ wrapper provides quantum resistance.
```

## 3. How these basic programs work together

- Run **pqc_keygen.c** once → creates a fresh `.kchain` file.  
- (Optional but recommended) Run the validator tools (`pqc_key_validator.c` or `validate_kchain.c`) on that file. They quickly prove the keys either are setup correctly (kchain validator) or they really work by signing and verifying small test messages (key validator).  
- Run **pqc_hybrid_signer_old.c** as many times as you want with the same `.kchain`, any role number, and any message → you get a hybrid signature each time.

Everything stays inside the `svc-wallet/` folder. No complicated setup.  

These basic versions are great for showcasing this idea of custom seeding. I use BTC (double-sha+base58) private key as an entropy inclusion because I use this for something on my own that uses keys that are similar but not compatable with BTC. BTC or Bitcoin was used in the original build because I did not have a working version of my double-shake+base58 at the time. Compile with liboqs + jansson + OpenSSL, run, and you have working example of potential post-quantum keys and signatures in minutes. This shows how there are processes that can work on smaller form factor machine and older hardware that can use any data to start the seeding and if we ran through this entire setup again, taking our output as input; we could potentially decouple the entire input->seed process.

This is not intended for direct use with bitcoin and real cryptographic keys that hold wealth, value or have the potential to do so until you have fully tested and verified you feel comfortable with this system & setup. This is 100% custom designed processing for a different project but seem notable in how the seed process worked and how I was using the output by wrapping a real sign with a real PQC sign. An *old sign to sign a new sign* (so to speak) to create a repo just for it.

---

