'use strict'

const { scryptSync, createCipheriv, createDecipheriv, randomBytes } = require('node:crypto')
const { Buffer } = require('node:buffer')
const m2m = require('m2m') 

/*
const buf = randomBytes(256)
const pw = buf.toString('hex')
let salt = pw.slice(0, 16)
let key = null
*/

function genKey(client){
    const buf = randomBytes(256)
    const pw = buf.toString('hex')
    let salt = pw.slice(0, 16)
    let key = scryptSync(pw, salt, 32)
    let kpl = JSON.stringify({ key:key.toString('hex') })

    // distribute encryption key to server using a secure channel   
    client.sendData('e-key', kpl, (data) => {
        console.log('e-key status:', data)
    })
    return key
}

// m2m client
let client = new m2m.Client()

m2m.connect('https://dev.node-m2m.com', () => {

    // device 200 access
    let c1 = client.accessDevice(200)

    // generate encryption key
    /*
        key = scryptSync(pw, salt, 32)
        let kpl = JSON.stringify({ key:key.toString('hex') })

        // distribute encryption key to server using a secure channel   
        c1.sendData('e-key', kpl, (data) => {
            console.log('e-key status:', data)
        })
    */ 

    let key = genKey(c1)
    
    setInterval(() => {
        key = genKey(c1)
    }, 10000) 

    // edge client
    let ec1 = new m2m.edge.client(8127, '127.0.0.1')

    // prepare encrypted payload for ec1.sendData('dec-data', pl, cb) method below
    const algorithm = 'aes-256-gcm' 
    //const iv = Buffer.alloc(16, 15) // fixed-value iv
    const iv = randomBytes(16)      // random iv
    const aad = Buffer.from(iv.toString(), 'hex')

    let ciphertext = null, tag = null
    
    try{
        const cipher = createCipheriv(algorithm, key, iv, {
            authTagLength: 16,
        })

        const plaintext = 'Hello world'

        cipher.setAAD(aad, {
          plaintextLength: Buffer.byteLength(plaintext),
        })
        ciphertext = cipher.update(plaintext, 'utf8', 'hex')
        cipher.final()
        tag = cipher.getAuthTag()
    }
    catch(e){
        console.log('dec-data encrypt error:', e.message)
    }

    let epl = { ciphertext:ciphertext, iv:iv.toString('hex'), tag:tag.toString('hex'), key:key.toString('hex') }
    let pl = JSON.stringify(epl)
       
    // wait for the server to receive the key 
    setTimeout(() => {    
        ec1.sendData('dec-data', pl , (data) => {
            console.log('ec1 dec-data:', data)
        })

        ec1.subscribe('enc-data', (data) => {
            if(!data){
                return
            }

            let dec = JSON.parse(data)
            let ciphertext = dec.ciphertext
            let iv = Buffer.from(dec.iv, 'hex')
            let tag = Buffer.from(dec.tag, 'hex')
            let aad = Buffer.from(iv.toString(), 'hex')
 
            try {
                const decipher = createDecipheriv(algorithm, key, iv, {
                  authTagLength: 16,
                })
                decipher.setAuthTag(tag)
                decipher.setAAD(aad, {
                  plaintextLength: ciphertext.length,
                })
                const receivedPlaintext = decipher.update(ciphertext, 'hex', 'utf8')
            
                decipher.final()

                console.log(receivedPlaintext)
            }
            catch (err) {
                console.log('enc-data decrypt erorr:', err.message)
            }
        })
    }, 3000)
})  
