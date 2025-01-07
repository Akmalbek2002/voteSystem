const crypto = require('crypto');

// RSA kalitlarni yaratish
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});

// Kalitlarni eksport qilish
module.exports = { publicKey, privateKey };
