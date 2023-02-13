'use strict'

const { scryptSync, createCipheriv, createDecipheriv, randomBytes } = require('node:crypto')
const { Buffer } = require('node:buffer')
const m2m = require('m2m')

let key = null 

function voltageSource(){
  return 50 + Math.floor(Math.random() * 10)
}

// m2m server
let device = new m2m.Device(200)

m2m.connect('https://dev.node-m2m.com', () => {

    device.dataSource('e-key', (data)=>{
        if(!data.payload){
            data.send('invalid key')
        }
        let dec = JSON.parse(data.payload) // ok but no need for m2m, parsing is done internally
        //let dec = data.payload  // ok
        key = Buffer.from(dec.key, 'hex')
        data.send('key recvd')
    })

    const algorithm = 'aes-256-gcm'

    //const pub_iv = Buffer.alloc(16, 1) // fixed value iv
    const pub_iv = randomBytes(16)      // random iv
    const pub_aad = Buffer.from(pub_iv.toString(), 'hex')

    // edge server
    m2m.edge.createServer(8127, '127.0.0.1', (server) => {

        server.publish('enc-data', (data) => {
    
            // start encryption only if key is available
            if(!key){
                return
            }        

            let ciphertext = null, tag = null

            try{
                const cipher = createCipheriv(algorithm, key, pub_iv, {
                    authTagLength: 16,
                })

                const plaintext = voltageSource().toString()
                //const plaintext = '25' // fixed-value voltage 
                console.log(plaintext)

                cipher.setAAD(pub_aad, {
                  plaintextLength: Buffer.byteLength(plaintext),
                })
                ciphertext = cipher.update(plaintext, 'utf8', 'hex')
                cipher.final()
                tag = cipher.getAuthTag()

                
                let epl = JSON.stringify({ ciphertext:ciphertext, iv:pub_iv.toString('hex'), tag:tag.toString('hex') })
                    
                // publish encrypted payload                
                data.send(epl)

            }
            catch(e){
                console.log('enc-data encrypt error:', e.message)
            }
        })

        server.dataSource('dec-data', (data) => {
            if(!data.payload){
                data.send('invalid payload')
            }

            let dec = JSON.parse(data.payload) 
            let ciphertext = dec.ciphertext
            let iv = Buffer.from(dec.iv, 'hex')
            let tag = Buffer.from(dec.tag, 'hex')
            //let key = Buffer.from(dec.key, 'hex')
            //const aad = Buffer.from('0123456789', 'hex')
            //const aad = Buffer.from('bading', 'hex')
            const aad = Buffer.from(iv.toString(), 'hex')

            try {
                const decipher = createDecipheriv(algorithm, key, iv, {
                  authTagLength: 16,
                })
                decipher.setAuthTag(tag)
                decipher.setAAD(aad, {
                  plaintextLength: ciphertext.length,
                })
                const rcvdPlaintext = decipher.update(ciphertext, 'hex', 'utf8')
           
                decipher.final()

                console.log(rcvdPlaintext)
                data.send('encryption success')

            }
            catch (err) {
              console.log('dec-data decrypt erorr:', err.message)
            }
        })
    })
})
