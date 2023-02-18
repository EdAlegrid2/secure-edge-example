'use strict'

const { scryptSync, createCipheriv, createDecipheriv, randomBytes } = require('node:crypto')
const { Buffer } = require('node:buffer')
const m2m = require('m2m')

let key = null 

function voltageSource(){
  return 50 + Math.floor(Math.random() * 10)
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
     * m2m server
     */
    let device = new m2m.Device(200)

    device.dataSource('e-key', (data)=>{
        if(!data.payload){
            data.send('invalid key')
        }
        let dec = JSON.parse(data.payload) // ok but no need for m2m, parsing is done internally
        //let dec = data.payload  // ok
        key = Buffer.from(dec.key, 'hex')
        data.send('key recvd')
    })

    /*** 
     * edge server
     */
    m2m.edge.createServer(8127, '127.0.0.1', (server) => {

        server.publish('enc-data', (data) => {
            // start encrypting only if key is available
            if(!key){
                return
            }
            let epl = encryptData(key, voltageSource().toString())
            data.send(epl)  
        })

        server.dataSource('dec-data', (data) => {
            if(!data||!data.payload){
                data.send('invalid payload')
            }
            if(!key){
                return
            }  
            let ddata = decryptData(key, data.payload)
            console.log(ddata) 
        })
    })
})
