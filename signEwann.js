const fs = require('fs');
const crypto = require('crypto')
const jose = require('node-jose')

function hash(payload){
    return crypto.createHash('sha512').update(payload).digest('hex');
}


async function signEwann(){
    keystore = jose.JWK.createKeyStore();

    const payload = fs.readFileSync('./EwannLegalPerson.json');
    const keyData = fs.readFileSync('./privateKey.key', 'utf-8');

    keystore.add(keyData.toString(), "pem").then((privateKey) => {
        const SD = JSON.parse(payload.toString());

        jose.JWS.createSign({format: 'compact',fields: { alg: 'PS256', "b64": false, crit : ['b64'] }},privateKey)
        .update(hash(payload))
        .final()
        .then(jws => {
            console.log("\n");
            console.log(jws);
        })

    })
}


signEwann();