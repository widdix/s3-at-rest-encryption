# S3 At-Rest-Encryption

Read the blog post: https://cloudonaut.io/encrypting-sensitive-data-stored-on-s3/

## AWS SDK + KMS

Before you can start, you have to generate an encrypted data key using the KMS service. Replace `KEY_ID_OR_ARN` with the id or ARN of your KMS CMK. 

> You can either use a AWS managed CMK or a customer managed CMK!

```
node cli.js create-data-key KEY_ID_OR_ARN
```

The encrypted data key will be temporarily stored (cached) in your current working directory as `data.key`. The file is not needed for decryption! You can regenerate it at any time.

### Encrypt

Now, you can encrypt a local file and upload it to S3. Replace `FILE` with the path the the local file, and `S3URI` with the location on S3, such as `s3://bucket/key`.

```
node cli.js encrypt-with-kms FILE S3URI
```

How it works:

1. The  temporary (cached) and encrypted `data.key` file is send to KMS service for decryption. Only if you still have permissions to decrypt the data key this operation will succeed.
2. The local file is read into memory.
3. An [initialization vector](https://en.wikipedia.org/wiki/Initialization_vector) (IV) is generated.
4. The aes256 algorithm is used to encrypt the data in memory.
5. A header (8 bytes), the encrypted data key, the IV (8 bytes), combined with the encrypted data are uploaded to S3.

### Decrypt

Once a file is uploaded to S3, you can also download the file and decrypt it again locally. Replace `S3URI` with the location on S3 and `FILE` with the path where the local file should be saved.

```
node cli.js decrypt-with-kms S3URI FILE
```

How it works:

1. The S3 object is downloaded from S3 into memory.
2. The first 8 bytes are interpreted as the header.
3. The following bytes (length in the header) are interpreted as the encrypted data key.
4. The encrypted data key is send to the KMS service for decryption. Only if you still have permissions to decrypt the data key this operation will succeed.
5. The following 8 bytes are interpreted as the IV.
6. The rest of the data in memory is decrypted using the aes256 algorithm.
7. The decrypted data is written to a local file.
