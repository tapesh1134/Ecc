const eccrypto = require('eccrypto');
const crypto = require('crypto');
const EC = require('elliptic');

// Initialize ECC (Elliptic Curve Cryptography)
const ec = new EC.ec('secp256k1'); // Use the desired elliptic curve, such as secp256k1

// Generate ECC key pair
const keyPair = ec.genKeyPair();
const publicKeyHex = keyPair.getPublic('hex');
const privateKeyHex = keyPair.getPrivate('hex');
const aesKey = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

// Generate ECC key pair
const privateKeyA = eccrypto.generatePrivate();
const publicKeyA = eccrypto.getPublic(privateKeyA);

console.log('Private Key A:', privateKeyA.toString('hex'));
console.log('Public Key A:', publicKeyA.toString('hex'));

const plaintext = 'Hello, ECC Testing!';

// Sign the data using public key A
eccrypto.sign(privateKeyA, Buffer.from(plaintext)).then((signatureA) => {
    console.log('Signature A:', signatureA.toString('hex'));

    // Verify the signature using private key A
    eccrypto.verify((publicKeyA), Buffer.from(plaintext), signatureA).then((isValidA) => {
        if (isValidA) {
            console.log('Signature A is valid.');

            // Now, let's decrypt the data using both keys (for testing purposes)
            eccrypto.encrypt(publicKeyA, Buffer.from(plaintext)).then((encryptedData) => {
                eccrypto.decrypt(privateKeyA, encryptedData).then((decryptedA) => {
                    console.log('Decrypted with Private Key A:', decryptedA.toString('utf8'));
                });

                eccrypto.decrypt(publicKeyA, encryptedData).then((decryptedB) => {
                    console.log('Decrypted with Public Key A:', decryptedB.toString('utf8'));
                });
            });
        } else {
            console.log('Signature A is valid.');
        }
        const cipher1 = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
        let encryptedData1 = cipher1.update(plaintext, 'utf-8', 'base64');
        encryptedData1 += cipher1.final('base64');
        console.log('Encrypted Data using public:', encryptedData1);
        const signature1 = keyPair.sign(plaintext);

        // Verify the signature using the private key (for testing purposes)
        const isSignatureValid1 = keyPair.verify(plaintext, signature1);
        const aesDecipher1 = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
        let decryptedMessage1 = aesDecipher1.update(encryptedData1, 'base64', 'utf-8');
        decryptedMessage1 += aesDecipher1.final('utf-8');

        console.log('Decrypted Message private:', decryptedMessage1);
    });
});


