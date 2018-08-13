const commandKMS = require('./kms.js');

const run = async (argv) => {
  if (argv[2] === 'create-data-key') {
    return await commandKMS.create(argv[3]);
  } else if (argv[2] === 'encrypt-with-kms') {
    return await commandKMS.encrypt(argv[3], argv[4]);
  } else if (argv[2] === 'decrypt-with-kms') {
    return await commandKMS.decrypt(argv[3], argv[4]);
  }  else {
    throw new Error('unsupported command');
  }
};

run(process.argv)
  .then(console.info)
  .catch(err => console.error(err));
