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
        //let dec = JSON.parse(data.payload) // no need for m2m, parsing is done internally
        let dec = data.payload 
        key = Buffer.from(dec.key, 'hex')
        data.send('key recvd')
    })

    const algorithm = 'aes-256-cbc'

    //const Iv = Buffer.alloc(16, 1) // fixed value iv
    const Iv = randomBytes(16)      // random iv

    // edge server
    m2m.edge.createServer(8127, '127.0.0.1', (server) => {

        server.dataSource('dec-data', (data) => {
            if(!data.payload){
                data.send('invalid payload')
            }

            let dec = JSON.parse(data.payload)
            let encrypted = dec.encrypted
            let iv = Buffer.from(dec.iv, 'hex')
      
            try{
                const decipher = createDecipheriv(algorithm, key, iv)
                let decrypted = decipher.update(encrypted, 'hex', 'utf8');
                decrypted += decipher.final('utf8');
                console.log(decrypted);
                // send back decrypted data, for test only
                data.send(decrypted)
            }
            catch(e){
                console.log('dec-data decrypt error:', e.message);
            }
        
        })

        server.pub('enc-data', (data) => {
                
            let vs = voltageSource().toString()
            //let vs = '10' // constant voltage 
            console.log(vs)

            if(key){ 
                try{  
                    const cipher = createCipheriv(algorithm, key, Iv)
                    let encrypted = cipher.update(vs, 'utf8', 'hex')
                    encrypted += cipher.final('hex')

                    let epl = JSON.stringify({ encrypted:encrypted, iv:Iv.toString('hex') })
                    data.send(epl)
                }
                catch(e){
                    console.log('enc-data encrypt error:', e.message);
                }
            }
        })
    })
})
