import { expect, describe, it } from 'vitest'
import { main } from './signEwann'

// The two tests marked with concurrent will be run in parallel
describe('Verify shacl validation', () => {
  it.concurrent('should return true on valid registration', async ({expect}) => { 
    expect(await main('dist/registration_vp.json')).toBeTruthy()
   })
   it.concurrent('should return false on invalid registration', async ({expect}) => { 
    expect(await main('dist/registration_vp_invalid.json')).toBeFalsy()
   })

   it.concurrent('should return true on valid person', async ({expect}) => { 
    expect(await main('dist/person.json')).toBeTruthy()
   })
   it.concurrent('should return true on valid person with type in credential', async ({expect}) => { 
    expect(await main('dist/person2.json')).toBeTruthy()
   })

   it.concurrent('should return false on invalid person', async ({expect}) => { 
    expect(await main('dist/person_invalid.json')).toBeFalsy()
   })
})