'use strict'

const { scryptSync, pbkdf2Sync, createCipheriv, createDecipheriv, randomBytes, 
    generateKeyPairSync, publicEncrypt, privateDecrypt, publicDecrypt, createECDH, createHash, } = require('node:crypto')
const { Buffer } = require('node:buffer')
const edge = require('node-edge')

function aesEncrypt(key, plaintext, cb){
    const algorithm = 'aes-256-gcm'
    const iv = randomBytes(16)
    const aad = Buffer.from(iv.toString('utf8'), 'hex')
    let ciphertext = null, tag = null
    
    try{
        const cipher = createCipheriv(algorithm, key, iv, {
            authTagLength: 16,
        })
        cipher.setAAD(aad, {
          plaintextLength: Buffer.byteLength(plaintext),
        })
        ciphertext = cipher.update(plaintext, 'utf8', 'hex')
        cipher.final()
        tag = cipher.getAuthTag()

        let epl = JSON.stringify({ ciphertext:ciphertext, iv:iv.toString('hex'), tag:tag.toString('hex') })

        if(cb){
           return cb(epl)
        }
        return epl
    }
    catch(e){
        console.log('aesEncrypt error:', e.message)
        if(cb){
            return cb(e.message)
        }
        return e.message
    }
}

function publicEncryptData(data){
    let tmp = {}
    const rd = randomBytes(16)
    try{
        if(data.rpk){ // rsa public key   
            tmp.msg1 =  'Captain you are so cute, I love you ' + rd.toString('hex') 
            tmp.derivedKey1 = scryptSync(data.rpk, data.salt, 32) // derive a symmetric key using scrypt from the rsa public key
            data.ciphertext1 = aesEncrypt(tmp.derivedKey1, tmp.msg1 ) // encrypt the msg using symmetric 'aes-256-gcm'
            data.enc_derivedKey1 = (publicEncrypt(data.rpk, tmp.derivedKey1)).toString('base64') // buffer
        } 
    }
    catch(e){
        console.log('encrypt1 error:', e.message)
    }

    try{
        if(data.sepk){ // server ec public key
            tmp.clientEC = createECDH('secp521r1') // create a client Elliptic Curve Diffie-Hellman (ECDH) key exchange object to generate a public key and a shared secret
            data.cepk = tmp.clientEC.generateKeys('base64', 'compressed') // generate a client ec public key before generating a shared secret
            tmp.sharedSecret = tmp.clientEC.computeSecret( Buffer.from( data.sepk , 'base64') ) // generate a shared secret from the server ec public key

            tmp.msg2 = 'Marlene, you decorated my life. Sam, I am so proud of you ' + rd.toString('hex')
            tmp.derivedKey2 = pbkdf2Sync(tmp.sharedSecret, data.salt, 100000, 32, 'sha512') // derive a symmetric key using pbkdf2 from ec shared secret
            data.ciphertext2 = aesEncrypt(tmp.derivedKey2, tmp.msg2 ) // encrypt the msg using symmetric 'aes-256-gcm'
        }
    }
    catch(e){
        console.log('encrypt2 error:', e.message)
    }

    /*try{
        if(data.rpk){ // rsa public key
            tmp.msg3 = 'edo pogi ka '+rd.toString('base64') // only a very short msg can be encrypted
            tmp.ciphertext3 = publicEncrypt(data.rpk, tmp.msg3) // encrypt msg directly using the rsa public key
            data.ciphertext3 = tmp.ciphertext3.toString('hex')
        }
    }
    catch(e){
        console.log('encrypt3 error:', e.message)
    }*/

    tmp = {}
    return data
}

let ec1 = new edge.client(8130)

setInterval(() => {

    ec1.read('key-pair', (data) => {
        //console.log('data', data)
        if(data.toString() === 'false'){
            console.log('request rejected')
        }
        else{  
            // epl.rpk  is the rsa public key
            // epl.sepk is the server ec public key
            const epl = publicEncryptData(data)

            setImmediate(() => {
                ec1.send('key-pair', epl, (result) => {
                    console.log('result:', result)
                })
            })
        }
    })

}, 3000)

