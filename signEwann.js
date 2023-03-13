const fs = require('fs');
const crypto = require('crypto')
const jose = require('jose')
const axios = require('axios')
const JsonLdParser = require("jsonld-streaming-parser").JsonLdParser;
const SHACLValidator = require('rdf-validate-shacl')
const factory = require('rdf-ext');
const { Readable } = require('stream');

function hash(payload) {
    const payloadHash = crypto.createHash('sha256').update(payload).digest('hex');
    return payloadHash;
}


function proof(jws) {
    return {
        "type": "JsonWebSignature2020",
        "created": "2023-02-09T16:00:15.219Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:web:raw.githubusercontent.com:egavard:payload-sign:master",
        "jws": jws
    }

}

async function signEwann() {

    const payloadJSON = fs.readFileSync('./EwannLegalPerson.json', 'utf-8');
    const payload = JSON.parse(payloadJSON.toString())
    const payloadNormalized = await axios.post("http://localhost:3000/api/normalize", payload);

    const keyData = fs.readFileSync('./privateKey.key', 'utf-8');

    const rsaPrivateKey = await jose.importPKCS8(
        keyData,
        'PS256'
    )

    const jws = await new jose.CompactSign(new TextEncoder().encode(hash(payload.toString())))
        .setProtectedHeader({ alg: 'PS256', b64: false, crit: ['b64'] })
        .sign(rsaPrivateKey)


    payload.proof = proof(jws);
    console.log(payload);
}

async function validateShacl(){
    const schaclFile = await axios.get("https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes");
    const shaclStream = new Readable();
    shaclStream.push(Buffer.from(JSON.stringify(schaclFile.data)));
    shaclStream.push(null);


    const myParser = new JsonLdParser();
    const shapes = await factory.dataset().import(myParser.import(shaclStream))
    console.log(shapes)
    const validator = new SHACLValidator(shapes, null);

}


signEwann();
validateShacl();