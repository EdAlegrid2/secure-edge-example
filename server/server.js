//const { edge, createDevice } = require('m2m')
const m2m = require('m2m')

function tempSource(){
  return 20 + Math.floor(Math.random() * 10)
}

// edge server using local private tcp connection
let port = 8126, host = '192.168.0.113'

// m2m server using internet connection
let device = m2m.createDevice(100)

m2m.connect('https://dev.node-m2m.com', () => {
  device.publish('m2m-temperature', (data) => {
    let ts = tempSource()
    data.send(ts)
  })

  m2m.edge.createServer(port, (server) => {
    console.log('edge server 1 :', host, port)

    server.publish('edge-temp', (data) => {
      let ts = tempSource()
      //console.log('ts', ts)
      data.interval = 10000 
      data.send(JSON.stringify({value:ts}))
    })

    server.on('error', (err) => {
      console.log('server error', err.message);  
    })
  })
})
