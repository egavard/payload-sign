const fs = require('fs');
const crypto = require('crypto')
const jose = require('jose')
const axios = require('axios')
const jsonld = require('jsonld')
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

async function normalize(payload) {
    return await jsonld.canonize(payload, {
        algorithm: 'URDNA2015',
        format: 'application/n-quads'
      })
}

async function signEwann() {

    const payloadJSON = fs.readFileSync('./vp.json', 'utf-8');


    //Sign credential, then VP

    const verifiablePresentation = JSON.parse(payloadJSON.toString())
    const credentialNormalized = await normalize(verifiablePresentation.verifiableCredential[0])

    const keyData = fs.readFileSync('./privateKey.pem', 'utf-8');

    const rsaPrivateKey = await jose.importPKCS8(
        keyData,
        'PS256'
    )

    const credentialJws = await new jose.CompactSign(new TextEncoder().encode(hash(credentialNormalized.toString())))
        .setProtectedHeader({ alg: 'PS256', b64: false, crit: ['b64'] })
        .sign(rsaPrivateKey)


    verifiablePresentation.verifiableCredential[0].proof = proof(credentialJws);
    return verifiablePresentation;
}

async function validate(shapeStr, sdStream){
    const parserTTL = new ParserN3({ factory })
    const shapes = await factory.dataset().import(parserTTL.import(shapeStr))
    JsonLdParser
    const sds = await factory.dataset().import(parserTTL.import(sdStream))
    const validator = new SHACLValidator(shapes);

    const results = validator.validate(sds);
    console.log(results.conforms)
    console.log(results.results.map(result => `${result.path} => ${JSON.stringify(result.message[0].value)}`).join("\n"))

}

async function validateShacl(sd){
    const schaclFile = await axios.get("https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/participant");
    const shapeStream = new Readable();
    shapeStream.push(schaclFile.data);
    shapeStream.push(null);


    const payloadNormalized = await axios.post("http://localhost:3000/api/normalize", sd);
    const sdStream = new Readable();
   // sdStream.push(payloadNormalized.data.toString());
    sdStream.push(JSON.stringify(sd));
    sdStream.push(null);
    return validate(shapeStream, sdStream)
}

main = async () => {
    const sd = await signEwann();
    console.log(JSON.stringify(sd))
    // const shapeStr = fs.createReadStream("./person.ttl")
    // const sdStr = fs.createReadStream("./john.ttl")
    // await validate(shapeStr, sdStr);
    //await validateShacl(sd);
}

main();
