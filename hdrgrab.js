#!/usr/bin/env node

var argv = require('optimist').argv
var dns = require('dns')
var fs = require('fs')
var node_http = require('http')
var pcap = require("pcap")
var util = require('util')


var hdrgrab = {
  device: '',
  sniff_port: 80,
  captured_packets: 0,
  servers: {},
  pcap_session: undefined,
  drop_watcher: undefined,
  err: undefined,
  conn_headers: ['connection', 'keep-alive', 'te', 'transfer-encoding', 'upgrade'],

  clear: function () {
    var self = this
    self.packets = []
    self.capture = {sessions: {}}
    self.captured_packets = 0
    self.msgs = {}
    self.err = undefined
    if (self.drop_watcher) {
      clearInterval(self.drop_watcher)
    }
    self.drop_watcher = undefined
  },

  start_capture: function() {
    var self = this
    self.clear()
    var f = "tcp port " + self.sniff_port
    var b = 10
    // FIXME: where did error catch go?
    self.capture.start = new Date().getTime()
    self.pcap_session = pcap.createSession(self.device, f, (b * 1024 * 1024))
    this.setup_listeners()
    console.log("Sniffing on " + self.pcap_session.device_name + " port " + self.sniff_port)
    
    // Check for pcap dropped packets on an interval
    self.drop_watcher = setInterval(function () {
      var stats = self.pcap_session.stats()
      if (stats.ps_drop > 0) {
        // TODO: notify browser through err as well
        console.log(
          "dropped packets, need larger buffer or less work to do: " 
          + util.inspect(stats)
        )
      }
    }, 2000)
  },
  
  stop_capture: function () {
    var self = this
    if (self.pcap_session == undefined) {
      return
    }
    if (self.drop_watcher) {
      clearInterval(self.drop_watcher)
    }
    self.drop_watcher == undefined
    self.capture.end = new Date().getTime()
    self.pcap_session.close()
    self.pcap_session = undefined
    console.log("Stopped sniffing")
  },

  setup_listeners: function () {
    var self = this
    var tcp_tracker = new pcap.TCP_tracker()

    // listen for packets, decode them, and feed TCP to the tracker
    self.pcap_session.on('packet', function (raw_packet) {
      self.captured_packets += 1
      var packet = pcap.decode.packet(raw_packet)
      tcp_tracker.track_packet(packet)
    })
      
    tcp_tracker.on('http request', function (session, http) {
      self.print_hdrs(http.request.headers, session, "req")
    })

    tcp_tracker.on('http response', function (session, http) {
      self.print_hdrs(http.response.headers, session, "res")
    })

    tcp_tracker.on('http error', function (session, direction, error) {
      console.log(" HTTP parser error: " + error)
    })
    
    process.on('SIGINT', function () {
      console.log('Exiting.')
      var server_count = 0
      for (server in self.servers) {
        server_count += 1
        self.servers[server].on('close', function () {
          server_count -= 1
          if (server_count == 0) {
            process.exit(0)
          }
        })
        self.servers[server].end()
      }
      // if there aren't any servers
      process.exit(0)
    });
  },
  
  print_hdrs: function (headers, session, msg_type) {
    var self = this
    var name = self.parse_addr(session.dst)[0] + "-" + msg_type
    var server = self.servers[name]
    if (! server) {
      var server = fs.createWriteStream(name)
      self.servers[name] = server
    }
    
    for (line in headers) {
      var lc_hdr = line.toLowerCase()
      if (self.conn_headers.indexOf(lc_hdr) < 0) {
        server.write(line + ": " + headers[line] + "\n")
      }
    }
    server.write("\n")
  }, 
  
  parse_addr: function (addr) {
    return addr.split(":")
  }
}


// port to listen to 
var port = parseInt(argv._[0], 10)
if (port) {
  hdrgrab.sniff_port = port
}

// device to snoop on
var device = argv._[1]
if (device) {
  hdrgrab.device = device
}

hdrgrab.start_capture()