import ParserN3 from '@rdfjs/parser-n3';
import axios from 'axios';
import crypto from 'crypto';
import fs from 'fs';
import * as jose from 'jose';
import jsonld from "jsonld";
import factory from 'rdf-ext';
import SHACLValidator from 'rdf-validate-shacl';
import {Readable} from 'stream';

interface Proof {
    type: string
    created: string
    proofPurpose: string
    verificationMethod: string
    jws: string
}

export class SignatureService {


    hash(payload: string) {
        const payloadHash = crypto.createHash('sha256').update(payload).digest('hex');
        return payloadHash;
    }


    proof(jws: string): Proof {
        return {
            "type": "JsonWebSignature2020",
            "created": "2023-02-09T16:00:15.219Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:web:raw.githubusercontent.com:egavard:payload-sign:master",
            "jws": jws
        }

    }

    async normalize(payload: object) {
        return await jsonld.canonize(payload, {
            algorithm: 'URDNA2015',
            format: 'application/n-quads'
        })
    }

    async normalize2206(payload: object) {
        return (await axios.post('https://compliance.lab.gaia-x.eu/2206-unreleased/api/normalize', payload)).data;
    }

}

export class SHACLValidationService {
    parserTTL = new ParserN3({factory})

    /**
     *
     * @param shape path to the turtle shape file
     * @param data object representing data to validate
     */
    async validate(shape: string, data: object) {

        const shapeFromRegistry = (await axios.get("https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/trustframework")).data

        const shapeStr = new Readable()
        shapeStr.push(shapeFromRegistry)
        shapeStr.push(null)


        const dataRDF = await jsonld.toRDF(data, {format: 'application/n-quads'});
        const input = new Readable()
        input.push(dataRDF)
        input.push(null)


        const shapes = await factory.dataset().import(this.parserTTL.import(shapeStr))
        const sds = await factory.dataset().import(this.parserTTL.import(input))

        const validator = new SHACLValidator(shapes);

        return validator.validate(sds);
    }
}


async function signEwann(pathToData: string) {

    const payloadJSON = fs.readFileSync(pathToData, 'utf-8');
    const signService = new SignatureService();


    //Sign credential, then VP

    const verifiablePresentation = JSON.parse(payloadJSON.toString())
    for (const vc of verifiablePresentation.verifiableCredential) {
        const credentialNormalized = await signService.normalize(vc)

        const keyData = fs.readFileSync('dist/privateKey.pem', 'utf-8');

        const rsaPrivateKey = await jose.importPKCS8(
            keyData,
            'PS256'
        )

        const credentialJws = await new jose.CompactSign(new TextEncoder().encode(signService.hash(credentialNormalized.toString())))
            .setProtectedHeader({alg: 'PS256', b64: false, crit: ['b64']})
            .sign(rsaPrivateKey)


        vc.proof = signService.proof(credentialJws);

    }


    return {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "type": "VerifiablePresentation",
        "verifiableCredential": verifiablePresentation.verifiableCredential
    };
}

export async function main(payloadPath: string) {
    const shaclValidation = new SHACLValidationService()

    const sdRegistration = await signEwann(payloadPath);

    const validationResults = await shaclValidation.validate("dist/trustframework.ttl", sdRegistration);
    console.warn(`==== ${payloadPath} ==== ${validationResults.conforms}`)
    console.log(validationResults.results.map(result => `${result.path} => ${JSON.stringify(result.message[0].value)}`).join("\n"))
    console.log(JSON.stringify(sdRegistration))
    // if(validationResults.conforms){
    //     const complianceResult = await axios.post("https://compliance.lab.gaia-x.eu/development/api/credential-offers",sdRegistration)
    //     console.log(JSON.stringify(complianceResult.data))
    //     console.log(complianceResult.status)
    // }
    return validationResults.conforms
}

async function signEwann2206(pathToData: string) {

    const payloadJSON = fs.readFileSync(pathToData, 'utf-8');
    const signService = new SignatureService();


    //Sign credential, then VP

    const vc = JSON.parse(payloadJSON.toString())
    const credentialNormalized = await signService.normalize2206(vc)

    const keyData = fs.readFileSync('dist/privateKey.pem', 'utf-8');

    const rsaPrivateKey = await jose.importPKCS8(
        keyData,
        'PS256'
    )

    const credentialJws = await new jose.CompactSign(new TextEncoder().encode(signService.hash(credentialNormalized.toString())))
        .setProtectedHeader({alg: 'PS256', b64: false, crit: ['b64']})
        .sign(rsaPrivateKey)


    vc.proof = signService.proof(credentialJws);


    return vc;
}

export async function main2206(payloadPath: string) {
    const shaclValidation = new SHACLValidationService()

    const sdRegistration = await signEwann2206(payloadPath);

    const validationResults = await shaclValidation.validate("dist/trustframework.ttl", sdRegistration);
    console.warn(`==== ${payloadPath} ==== ${validationResults.conforms}`)
    console.log(validationResults.results.map(result => `${result.path} => ${JSON.stringify(result.message[0].value)}`).join("\n"))
    console.log(JSON.stringify(sdRegistration))
    // if(validationResults.conforms){
    //     const complianceResult = await axios.post("https://compliance.lab.gaia-x.eu/development/api/credential-offers",sdRegistration)
    //     console.log(JSON.stringify(complianceResult.data))
    //     console.log(complianceResult.status)
    // }
    return validationResults.conforms
}


// main('dist/service-offering.json');
// main('dist/registration_vp.json');
// main('dist/registration_vp_invalid.json');
// main('dist/person.json');
// main('dist/person_invalid.json');
// main('dist/person_linkedregistration.json')
// main('dist/invalid_person_linkedregistration.json')
main('dist/invalid-service-offering-type.json')
// main2206('dist/participant-sd.json')
// main2206('dist/service-sd.json')
