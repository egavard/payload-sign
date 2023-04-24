import {describe, it} from 'vitest'
import {main} from './signEwann'

// The two tests marked with concurrent will be run in parallel
describe('Verify shacl validation', () => {
    it('should return true on valid registration', async ({expect}) => {
        expect(await main('dist/registration_vp.json')).toBeTruthy()
    })
    it('should return false on invalid registration', async ({expect}) => {
        expect(await main('dist/registration_vp_invalid.json')).toBeFalsy()
    })

    it('should return true on valid person', async ({expect}) => {
        expect(await main('dist/person.json')).toBeTruthy()
    })
    it('should return true on valid person with type in credential', async ({expect}) => {
        expect(await main('dist/person2.json')).toBeTruthy()
    })

    it('should return false on invalid person', async ({expect}) => {
        expect(await main('dist/person_invalid.json')).toBeFalsy()
    })
    it('should return true on valid linked person registration', async ({expect}) => {
        expect(await main('dist/person_linkedregistration.json')).toBeTruthy()
    }, 10000)
    it('should return false on invalid linked person registration', async ({expect}) => {
        expect(await main('dist/invalid_person_linkedregistration.json')).toBeFalsy()
    })
    it('should return true on valid service offering with legal participant', async ({expect}) => {
        expect(await main('dist/service-offering.json')).toBeTruthy()
    })
    it('should return false on invalid service offering credential', async ({expect}) => {
        expect(await main('dist/service-offering_bad_structure.json')).toBeFalsy()
    })
    it('should return false on invalid linked service-offering providedBy', async ({expect}) => {
        expect(await main('dist/service-offering_bad_provided_by.json')).toBeFalsy()
    })
    it('should return true on service offering without proper type (managed by compliance)', async ({expect}) => {
        expect(await main('dist/invalid-service-offering-type.json')).toBeTruthy()
    })
})