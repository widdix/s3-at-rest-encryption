const util = require('util');
const fs = require('fs');
const crypto = require('crypto');
const url = require('url');

const AWS = require('aws-sdk');
const s3 = new AWS.S3({apiVersion: '2006-03-01'});
const kms = new AWS.KMS({apiVersion: '2014-11-01'});

const TEMP_DATA_KEY_FILE_NAME = 'data.key';
const HEADER_LENGTH = 8;
const IV_LENGTH = 8;

const writeFile = util.promisify(fs.writeFile);
const readFile = util.promisify(fs.readFile);

const generateIVBuffer = (keyBuffer) => {
  const salt = crypto.randomBytes(16);
  const iv = crypto.pbkdf2Sync(keyBuffer, salt, 100000, IV_LENGTH, 'sha512');
  return iv;
};

const parseS3Uri = (uri) => {
  const u = new url.URL(uri);
  if (u.protocol !== 's3:') {
    throw new Error('invalid S3 URI');
  }
  return {
    Bucket: u.hostname,
    Key: u.pathname
  };
};

const getDecryptedDataKeyBuffer = async (encryptedKeyBuffer) => {
  const data = await kms.decrypt({CiphertextBlob: encryptedKeyBuffer}).promise();
  return data.Plaintext;
};

exports.create = async (kmsKeyId) => {
  const data = await kms.generateDataKey({
    KeyId: kmsKeyId,
    KeySpec: 'AES_256'
  }).promise();
  await writeFile(TEMP_DATA_KEY_FILE_NAME, data.CiphertextBlob);
  return TEMP_DATA_KEY_FILE_NAME;
};

exports.encrypt = async (inputFile, s3Uri) => {
  const encryptedKeyBuffer = await readFile(TEMP_DATA_KEY_FILE_NAME);
  const decryptedKeyBuffer = await getDecryptedDataKeyBuffer(encryptedKeyBuffer);
  const plainBuffer = await readFile(inputFile);
  const ivBuffer = generateIVBuffer(decryptedKeyBuffer);
  const cipher = crypto.createCipheriv('aes256', decryptedKeyBuffer, ivBuffer.toString('hex'));
  const headerBuffer = Buffer.alloc(HEADER_LENGTH);
  headerBuffer.writeUInt8(1, 0); // header version
  headerBuffer.writeUInt8(0, 1); // reserved for future use
  headerBuffer.writeUInt8(0, 2); // reserved for future use
  headerBuffer.writeUInt8(0, 3); // reserved for future use
  headerBuffer.writeUInt32LE(encryptedKeyBuffer.length, 4); // length of encrypted data key
  const bodyBuffer = Buffer.concat([headerBuffer, encryptedKeyBuffer, ivBuffer, cipher.update(plainBuffer), cipher.final()]);
  const params = Object.assign({}, parseS3Uri(s3Uri), {Body: bodyBuffer});
  await s3.putObject(params).promise();
  return s3Uri;
};

exports.decrypt = async (s3Uri, outputFile) => {
  const params = parseS3Uri(s3Uri);
  const object = await s3.getObject(params).promise();
  const bodyBuffer = object.Body;
  const headerBuffer = bodyBuffer.slice(0, HEADER_LENGTH);
  const headerVersion = headerBuffer.readUInt8(0);
  if (headerVersion !== 1) {
    throw new Error('Unsupported header version');
  }
  const encryptedKeyLength = headerBuffer.readUInt32LE(4);
  const encryptedKeyBuffer = bodyBuffer.slice(8, 8 + encryptedKeyLength);
  const decryptedKeyBuffer = await getDecryptedDataKeyBuffer(encryptedKeyBuffer);
  const ivBuffer = bodyBuffer.slice(8 + encryptedKeyLength, 8 + encryptedKeyLength + IV_LENGTH);
  const decipher = crypto.createDecipheriv('aes256', decryptedKeyBuffer, ivBuffer.toString('hex'));
  const decryptedBuffer = Buffer.concat([decipher.update(bodyBuffer.slice(8 + encryptedKeyLength + IV_LENGTH)) , decipher.final()]);
  await writeFile(outputFile, decryptedBuffer);
  return outputFile;
};
