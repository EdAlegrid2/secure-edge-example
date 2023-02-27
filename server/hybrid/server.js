'use strict'

const { scryptSync, pbkdf2Sync, createCipheriv, createDecipheriv, randomBytes, 
    generateKeyPairSync, publicEncrypt, privateDecrypt, publicDecrypt, createECDH, createHash, } = require('node:crypto')
const { Buffer } = require('node:buffer')
const edge = require('node-edge')

/*** 
 * public key infrastructure
 */
let rejected = 0
let keyStore = []
let bufferDecrypt = []

function aesDecrypt(key, edata, cb){
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
        const plaintext = decipher.update(ciphertext, 'hex', 'utf8')
        decipher.final()
        if(cb){
            return cb(plaintext)
        }
        return plaintext
    }
    catch (e) {
        console.log('decrypt createDecipheriv erorr:', e.message)
        if(cb){
            return cb(e.message)
        }
        e.message
    }
} 

function startBufferDecryptProcess(){
    bufferDecrypt.forEach((cypherData, x) => {
        if(cypherData.iv){
            console.log('start decrypting process')
            try{
                setImmediate(() => {  
                    serverDecryptProcess(cypherData.tcp, cypherData.epl)
                    bufferDecrypt.splice(x, 1)
                })
            }
            catch(e){
                console.log('BufferDecryptProcess error:', e.message)
            }
        }
    })
}

function genKeyPair(cb){

    if(keyStore.length > 10){
        console.log('start BufferDecryptProcess')
        cb('false')
        setImmediate(() => { 
            startBufferDecryptProcess()
        })
        return 
    }

    let pl = {}, tmp = {} 
    const buf = randomBytes(16)  
    const pp = buf.toString('base64')
        
    try{
        // generate rsa key pair
        const { publicKey, privateKey,} = generateKeyPairSync('rsa', {
          modulusLength: 4096,
          publicKeyEncoding: {
            type: 'spki',
            format: 'pem',
          },
          privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
            cipher: 'aes-256-cbc',
            passphrase: pp.toString('base64') // 'top secret',
          },
        });

        // rsa key pair
        tmp = {privKey:privateKey , pubKey:publicKey, passphrase:pp}
        pl.rpk = publicKey

        tmp.done = false 
        
        // generate server ec private and public key
        tmp.server = createECDH('secp521r1') // create a server Elliptic Curve Diffie-Hellman (ECDH) key exchange object
        tmp.server.setPrivateKey(
            //createHash('sha512').update('server-in-wonderland', 'utf8').digest(), // fixed
            //createHash('sha512').update(publicKey, 'utf8').digest(),  // using rsa public key OK
            createHash('sha512').update(pp, 'utf8').digest(),  // using the passphrase pp OK
        );
        tmp.serverPublicKey = tmp.server.generateKeys('base64', 'compressed'); 
        pl.sepk = tmp.serverPublicKey // server ec public key

        // create a random iv
        randomBytes(16, (err, buf) => { // 16 bytes
          if (err) return console.log('randomBytes iv error', err.message)
          pl.iv = buf.toString('hex') // always use hex to get the correct byte size
          tmp.iv = pl.iv

          // create a random salt  
          randomBytes(16, (err, buf) => { // 16 bytes
            if (err) return console.log('randomBytes salt error', err.message)
            pl.salt = buf.toString('hex')
            tmp.salt = pl.salt 

            keyStore.push(tmp)
            setImmediate(() => { 
                cb(pl)
                tmp = {}
            }) 
          })
        })
    }
    catch(e){
        console.log('genKeyPair error', e.message)
    }

    setImmediate(() => { 
       keyStore.forEach((keySet, x) => {
            if(keySet.done){
                console.log('removing used public key pairs')
                try{  
                    keyStore.splice(x, 1)
                }
                catch(e){
                    console.log('keyStore.splice error:', e.message)
                }
            }
        })
    })
}

function serverDecryptProcess(tcp, epl){

    if(!epl.iv){
        console.log('missing epl.iv')
        return
    }

    keyStore.forEach((keySet, x) => {
        try{ 
            if(keySet.done){
                console.log('*removing used public key pairs')
                try{  
                    keyStore.splice(x, 1)
                }
                catch(e){
                    console.log('keyStore.splice error:', e.message)
                }
            }
            if(epl.iv && keySet.iv === epl.iv && keySet.done === false){
                let tmp = {}
                
                // rsa 2 step process
                // rsa public key is not needed anymore
                // 1. decrypt 'aes-256-gcm' symmetric key using the rsa private key 
                if(epl.enc_derivedKey1 && epl.ciphertext1){
                    tmp.derivedKey1 = privateDecrypt( { key:keySet.privKey, passphrase: keySet.passphrase }, Buffer.from( epl.enc_derivedKey1 , 'base64') ) // hex
                    // 2. decrypt cyphertext data from the derived key  
                    let decrypted_data1 = aesDecrypt(tmp.derivedKey1, epl.ciphertext1)
                    console.log('decrypted_data1', decrypted_data1)
                }

                // ecdh 3 step process
                // ecdh private key is not needed or rsa private key    
                // 1. generate the shared secret from the client ec public key (this is different from the server ec public key)
                if(epl.cepk && epl.ciphertext2){
                    tmp.sharedSecret = keySet.server.computeSecret( Buffer.from( epl.cepk , 'base64') ) // base64 string input
                    // 2. derived the key from shared secret 
                    tmp.derivedKey2 = pbkdf2Sync(tmp.sharedSecret, epl.salt, 100000, 32, 'sha512') // use epl.salt instead of keySet.salt
                    // 3. decrypt cyphertext data from the derived key    
                    let decrypted_data2 = aesDecrypt(tmp.derivedKey2, epl.ciphertext2)
                    console.log('decrypted_data2', decrypted_data2)
                }

                // decrypt data directly using pk, not really of any use for longer data // good for key encryption
                if(epl.ciphertext3){  
                    tmp.decrypted_data3 = privateDecrypt( { key: keySet.privKey, passphrase: keySet.passphrase }, Buffer.from( epl.ciphertext3, 'base64') )
                    console.log('tmp.decrypted_data3', tmp.decrypted_data3.toString())
                }

                //tcp.end('success') // client connection error: write after end getting

                keySet.done = true;
                tmp = {}
                // option to dispose used key pair variables immediately
                /*if(keySet.done){
                    keyStore.splice(x, 1)
                }*/ 
                console.log('keyStore size', keyStore.length)
                console.log('bufferDecrypt size', bufferDecrypt.length)
    
            }
        }
        catch(e){
            console.log('decryption process error', e.message)
        }
    }) 
}
  
/*** 
 * edge server
 */
edge.createServer(8130, (server) => {

    server.dataSource('key-pair', (tcp) => {
        if(tcp.payload){

            // real-time decrypt process
            let epl = tcp.payload
            setImmediate(() => {               
                serverDecryptProcess(tcp, epl)
            })

            tcp.send('recvd ciperData')

            // store key pair in mem store for later processing  
            let match = true
            let cypherData = { iv:epl.iv, epl:epl, tcp:tcp }
            keyStore.forEach((keySet, x) => {
                if(keySet.iv === epl.iv && keySet.done === false){
                    match = false
                    
                    bufferDecrypt.push(cypherData)
                }
            })
            if(match){
                bufferDecrypt.push(cypherData)
            }
        }
        else{
            genKeyPair((pl) => {
                tcp.send(pl)
            })
        }
    })

    server.on('connection', (count) => {
       console.log('client count:', count)
    })

    server.on('error', (err) => {
       console.log('error:', err.message)
    })

    setImmediate(() => {
        console.log('server.listening', server.listening)			
        console.log('server.address()', server.address())
    })
})

