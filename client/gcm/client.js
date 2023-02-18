'use strict'

const { scryptSync, createCipheriv, createDecipheriv, randomBytes } = require('node:crypto')
const { Buffer } = require('node:buffer')
const m2m = require('m2m') 

function genKey(client){
    const buf = randomBytes(256)
    const pw = buf.toString('hex')
    const salt = pw.slice(0, 16)
    const key = scryptSync(pw, salt, 32)
    return key
}

function encryptData(key, plaintext, cb){
    const algorithm = 'aes-256-gcm'
    //const iv = Buffer.alloc(16, 15) // fixed-value iv
    const iv = randomBytes(16)      // random iv
    const aad = Buffer.from(iv.toString('utf8'), 'hex')
    let ciphertext = null, tag = null
    
    try{
        const cipher = createCipheriv(algorithm, key, iv, {
            authTagLength: 16,
        })
        //const plaintext = 'Hello world'
        cipher.setAAD(aad, {
          plaintextLength: Buffer.byteLength(plaintext),
        })
        ciphertext = cipher.update(plaintext, 'utf8', 'hex')
        cipher.final()
        tag = cipher.getAuthTag()

        let edata = { ciphertext:ciphertext, iv:iv.toString('hex'), tag:tag.toString('hex') }
        let epl = JSON.stringify(edata)

        if(cb){
           return cb(epl)
        }
        return epl
    }
    catch(e){
        console.log('encrypt createCipheriv error:', e.message)
        if(cb){
            return cb(e.message)
        }
        return e.message
    }
}

function decryptData(key, edata, cb){
    //console.log('decryptData', edata)
    const algorithm = 'aes-256-gcm'
    try {
        const dec = JSON.parse(edata)
        const ciphertext = dec.ciphertext
        const iv = Buffer.from(dec.iv, 'hex')
        const tag = Buffer.from(dec.tag, 'hex')
        const aad = Buffer.from(iv.toString(), 'hex')

        const decipher = createDecipheriv(algorithm, key, iv, {
          authTagLength: 16,
        })
        decipher.setAuthTag(tag)
        decipher.setAAD(aad, {
          plaintextLength: ciphertext.length,
        })
        const receivedPlaintext = decipher.update(ciphertext, 'hex', 'utf8')
        decipher.final()
        //console.log(receivedPlaintext)
        if(cb){
            return cb(receivedPlaintext)
        }
        return receivedPlaintext
    }
    catch (e) {
        console.log('decrypt createDecipheriv erorr:', e.message)
        if(cb){
            return cb(e.message)
        }
        e.message
    }
} 

m2m.connect('https://dev.node-m2m.com', () => {

    /*** 
     * m2m client
     */
    let client = new m2m.Client()

    // device 200 access
    let c1 = client.accessDevice(200)

    // generate encryption key
    let key = genKey()
    
    setInterval(() => {
        key = genKey()
        let kpl = JSON.stringify({ key:key.toString('hex') })
        // distribute encryption key to server using a secure channel   
        c1.sendData('e-key', kpl, (data) => {
            console.log('e-key status:', data)
        })
    }, 60000) 

    /*** 
     * edge client
     */
    let ec1 = new m2m.edge.client(8127, '127.0.0.1')

    ec1.on('ready', (data) => {
        //console.log('ec1 ready', data)
        let kpl = JSON.stringify({ key:key.toString('hex') })
        // distribute encryption key to server using a secure channel   
        c1.sendData('e-key', kpl, (data) => {
            console.log('e-key status:', data)
        })
    })

    ec1.on('error', (e) => {
        console.log('ec1 error', e.message)
    })
  
    // prepare encrypted payload for ec1.sendData('dec-data', pl, cb) method below
    //let pl = encryptData(key, 'pogi ka ed super')

    // wait for the server to receive the key 
    setTimeout(() => {
        // prepare encrypted payload for ec1.sendData('dec-data', pl, cb) method below
        let pl = encryptData(key, 'pogi ka ed super')

        ec1.sendData('dec-data', pl , (data) => {
            console.log('ec1 dec-data:', data)
        })

        ec1.subscribe('enc-data', (data) => {
            if(!data){
                return
            }
            let ddata = decryptData(key, data)
            console.log(ddata) 
        })
    }, 3000)
})  
