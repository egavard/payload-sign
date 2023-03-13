const fs = require('fs');
const crypto = require('crypto')
const jose = require('jose')
const axios = require('axios')
const JsonLdParser = require("jsonld-streaming-parser").JsonLdParser;
const SHACLValidator = require('rdf-validate-shacl')
const factory = require('rdf-ext');
const { Readable } = require('stream');
const ParserN3 = require('@rdfjs/parser-n3')

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
    const payloadNormalized = await axios.post("https://compliance.lab.gaia-x.eu/development/api/normalize", payload);

    const keyData = fs.readFileSync('./privateKey.pem', 'utf-8');

    const rsaPrivateKey = await jose.importPKCS8(
        keyData,
        'PS256'
    )

    const jws = await new jose.CompactSign(new TextEncoder().encode(hash(payload.toString())))
        .setProtectedHeader({ alg: 'PS256', b64: false, crit: ['b64'] })
        .sign(rsaPrivateKey)


    payload.proof = proof(jws);
    console.log(payload);
    return payload;
}

async function validateShacl(sd){
    const schaclFile = await axios.get("https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/participant");

    const parserTTL = new ParserN3({ factory })

    const shapeStream = new Readable();
    shapeStream.push(schaclFile.data);
    shapeStream.push(null);

    
    const shapes = await factory.dataset().import(parserTTL.import(shapeStream))

    const payloadNormalized = await axios.post("https://compliance.lab.gaia-x.eu/development/api/normalize", sd);
    const sdStream = new Readable();
    sdStream.push(payloadNormalized.data.toString());
    sdStream.push(null);



    const sds = await factory.dataset().import(parserTTL.import(sdStream))
    const validator = new SHACLValidator(shapes);

    const results = validator.validate(sds);
    console.log(results.conforms)


}

main = async () => {
    const sd = await signEwann();
    await validateShacl(sd);
}

main();
