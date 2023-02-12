'use strict'

const { scryptSync, createCipheriv, createDecipheriv, randomBytes } = require('node:crypto')
const { Buffer } = require('node:buffer')
const m2m = require('m2m'); 

const buf = randomBytes(256)
const pw = buf.toString('hex')
let salt = pw.slice(0, 16);
let key = null

// m2m client
let client = new m2m.Client()

m2m.connect('https://dev.node-m2m.com', () => {

    // device 200 access
    let c1 = client.accessDevice(200)

    // generate encryption key
    key = scryptSync(pw, salt, 32)

    let c1pl = { key:key.toString('hex') }

    // distribute encryption key to server using a secure channel   
    c1.sendData('e-key', c1pl, (data) => {
        console.log('e-key status:', data);
    })

    // edge client section
    let ec1 = new m2m.edge.client(8127, '127.0.0.1')

    // prepare encrypted payload for ec1.sendData('dec-data', pl, cb) method below
    const algorithm = 'aes-256-cbc'
    //const iv = Buffer.alloc(16, 15) // fixed-value iv
    const iv = randomBytes(16)      // random iv
    let encrypted = ''
    try{
        const cipher = createCipheriv(algorithm, key, iv)
        encrypted = cipher.update('bading ka Rv, super', 'utf8', 'hex')
        encrypted += cipher.final('hex')
        //console.log(encrypted) 
    }
    catch(e){
        console.log('dec-data encrypt error:', e.message);
    }

    let ecPl = { encrypted:encrypted, iv:iv.toString('hex') }
    let ecs = JSON.stringify(ecPl)
    
    // wait for the key distribution to server 
    setTimeout(() => {    
        ec1.sendData('dec-data', ecs , (data) => {
            console.log('ec1 dec-data', data)
        })

        ec1.sub('enc-data', (data) => {
            if(!data){
                return
            }

            let dec = JSON.parse(data)
            let encrypted = dec.encrypted
            let iv = Buffer.from(dec.iv, 'hex') // iv from received data
            //const Iv = Buffer.alloc(16, 1) // fixed-value iv
            
            if(key && iv && encrypted){
                try{  
                    const decipher = createDecipheriv(algorithm, key, iv)
                    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
                    decrypted += decipher.final('utf8');
                    console.log('ec1 decrypted dec-data', decrypted);
                }
                catch(e){
                    console.log('enc-data decrypt error:', e.message);
                }
            }    
        })
    }, 3000)

})  
