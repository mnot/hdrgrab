#!/usr/bin/env node

var argv = require('optimist').argv
var dns = require('dns')
var fs = require('fs')
var node_http = require('http')
var pcap = require("pcap")
var util = require('util')
var url = require('url')


var hdrgrab = {
  device: '',
  sniff_port: 80,
  captured_packets: 0,
  har: {
    log: {
        version: "1.2",
        creator: {
          name: "hdrgrab",
          version: "0.2.1"
        },
        entries: []
    }
  },
  pcap_session: undefined,
  drop_watcher: undefined,
  err: undefined,
  outfile_name: "grab.har",

  clear: function () {
    var self = this
    self.capture = {sessions: {}}
    self.captured_packets = 0
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

    tcp_tracker.on("start", function (session) {
      var conn = self.get_conn(session)
      conn.start = session.current_cap_time
    })

    tcp_tracker.on("end", function (session) {
      var conn = self.get_conn(session)
      conn.end = session.current_cap_time
    })
      
    tcp_tracker.on('http request', function (session, http) {
      var conn = self.get_conn(session)
      http.request.start_time = session.current_cap_time
      conn.outstanding_reqs.push(http.request)
    })

    tcp_tracker.on('http request complete', function (session, http) {
      var conn = self.get_conn(session)
      var req = conn.outstanding_reqs[conn.outstanding_reqs.length - 1]
      req.done_time = session.current_cap_time
    })

    tcp_tracker.on('http response', function (session, http) {
      var conn = self.get_conn(session)
      var req = conn.outstanding_reqs[conn.outstanding_reqs.length - 1]
      req.res_start_time = session.current_cap_time
    })

    tcp_tracker.on('http response complete', function (session, http) {
      var conn = self.get_conn(session)
      var req = conn.outstanding_reqs.shift()
      var res = http.response
      res.done_time = session.current_cap_time
      var base = "http://" + self.getHdr('Host', req.headers, 'localhost')
      var entry = {
        startedDateTime: self.ISODateString(req.start_time),
        time: Math.floor((res.done_time - req.start_time)),
        request: {
            method: req.method,
            url: url.resolve(base, req.url),
            httpVersion: "HTTP/" + req.http_version,
            queryString: [],
            cookies: [],
            headers: self.push_hdrs(req.headers),
            headersSize: -1,
            bodySize: req.body_len
        },
        response: {
            status: res.status_code,
            statusText: "",
            httpVersion: "HTTP/" + res.http_version,
            cookies: [],
            headers: self.push_hdrs(res.headers),
            content: {
              size: res.body_len,
              mimeType: self.getHdr('Content-Type', res.headers, 'application/octet-stream')
            },
            redirectURL: "",
            headersSize: -1,
            bodySize: res.body_len
        },
        cache: {},
        timings: {
          send: Math.floor((req.done_time - req.start_time)),
          wait: Math.floor((req.res_start_time - req.done_time)),
          receive: Math.floor((res.done_time - req.res_start_time))
        },
        serverIPAddress: conn.server,
        connection: conn.local_port
      }
      self.har.log.entries.push(entry)
    })

    tcp_tracker.on('http error', function (session, direction, error) {
      console.log(" HTTP parser error: " + error)
    })
    
    process.on('SIGINT', function () {
      self.stop_capture()
      var outfile = fs.openSync(self.outfile_name, 'w')
      var har_text = JSON.stringify(self.har)
      fs.write(outfile, har_text, 0, har_text.length, null, 
        function () { process.exit(0) })
    });
  },

  push_hdrs: function (hdrs) {
    var dest = []
    for (var hdr in hdrs) {
      if (hdrs.hasOwnProperty(hdr)) {
        var val = hdrs[hdr];
        dest.push({
          name: hdr,
          value: val
        })
      }
    }
    return dest
  },
    
  // given a TCP session, return the relevant data structure in self.capture
  get_conn: function (tcp_session) {
    var self = this
    var server
    var local_port
    if (tcp_session.dst.split(":")[1] == self.sniff_port) {
      server = tcp_session.dst.split(":")[0]
      local_port = tcp_session.src.split(":")[1]
    } else {
      server = tcp_session.src.split(":")[0]
      local_port = tcp_session.dst.split(":")[1]
    }
    return self._get_conn(server, local_port)
  },
  
  // given a server and local_port, return the relevant data structure  
  _get_conn: function (server, local_port) {
    if (this.capture.sessions[server] == undefined) {
      this.capture.sessions[server] = {}
    }
    var server_conn = this.capture.sessions[server]
    if (server_conn[local_port] == undefined) {
      server_conn[local_port] = {
        'server': server,
        'local_port': local_port,
        'outstanding_reqs': [],
      }
    }
    return server_conn[local_port]
  },
  
  ISODateString: function (di) {
    function pad (n) {return n<10 ? '0'+n : n}
    d = new Date (di)
    return d.getUTCFullYear()+'-'
      + pad(d.getUTCMonth()+1)+'-'
      + pad(d.getUTCDate())+'T'
      + pad(d.getUTCHours())+':'
      + pad(d.getUTCMinutes())+':'
      + pad(d.getUTCSeconds())+'Z'
  }, 
  
  getHdr: function (name, hdrs, default_val) {
    for (hdr in hdrs) {
      if (hdr.toLowerCase() == name.toLowerCase()) {
        return hdrs[hdr]
      }
    }
    return default_val
  }
}

// output file
var outfile = argv.o
if (outfile) {
  hdrgrab.outfile_name = outfile  
}

// port to listen to 
var port = argv.p
if (port) {
  hdrgrab.sniff_port = parseInt(port, 10)
}

// device to snoop on
var device = argv.i
if (device) {
  hdrgrab.device = device
}

hdrgrab.start_capture()