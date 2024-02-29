const Bson = require('bson');
const Net = require('net');
const EventEmitter = require('events');
const WebSocket = require('ws');
require('log-timestamp');

function random(len) {
    len = len || 32;
    const $chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';
    const maxPos = $chars.length;
    let pwd = '';
    for (i = 0; i < len; i++) {
        pwd += $chars.charAt(Math.floor(Math.random() * maxPos));
    }
    return pwd;
}

const wsURL = 'ws://<server-address>:3333';
const port = '<vscode-server-port>';
const localPort = '<local-port>';

console.time();
const eventEmitter = new EventEmitter();
const ws = new WebSocket(wsURL);
const wsSessionID = `s-${random(10)}`;
ws.on('open', function () {
    console.info('WebSocket connected');
    const json = JSON.stringify({
        Type: 'PtyStart',
        Data: {
            SessionId: wsSessionID,
            Cols: 100,
            Rows: 50,
        }
    });
    ws.send(json);
});

ws.on('error', function (err) {
    console.log('PTY ERROR: ', err);
});

ws.on('message', function (data, isBinary) {
    try {
        if (!isBinary) {
            const msg = JSON.parse(data);
            if (msg.Type == 'PtyReady') {
                console.log('receive PtyReady');
            }
            return;
        }
        if (isBinary) {
            const msg = Bson.deserialize(data);
            proxyID = msg.Data.Data.ProxyId;
            if (msg.Type == 'PtyProxyReady') {
                const proxyEvent = `${proxyID}#ready`;
                eventEmitter.emit(proxyEvent, '');
            } else if (msg.Type == 'PtyProxyData') {
                const proxyEvent = `${proxyID}#data`;
                data = msg.Data.Data.Data;
                eventEmitter.emit(proxyEvent, data);
            } else if (msg.Type == 'PtyProxyClose') {
                const proxyEvent = `${proxyID}#close`;
                eventEmitter.emit(proxyEvent, '');
            } else {
                console.log('WS MSG ERROR: unknown proxy msg');
            }
        }
    } catch (e) {
        console.error('WS MSG ERROR: ', e);
    }
});

function proxyStart(proxyID, port) {
    const msg = {
        Type: 'PtyProxyNew',
        Data: {
            SessionId: wsSessionID,
            CustomData: '',
            Data: {
                ProxyId: proxyID,
                Port: port,
                Ip: '127.0.0.1',
            },
        }
    };
    console.log(proxyID, 'send PtyProxyNew');
    ws.send(Bson.serialize(msg));
}

function proxyData(proxyID, data) {
    const msg = {
        Type: 'PtyProxyData',
        Data: {
            SessionId: wsSessionID,
            CustomData: '',
            Data: {
                ProxyId: proxyID,
                Data: data,
            },
        }
    };
    // console.log(proxyID, 'send PtyProxyData');
    ws.send(Bson.serialize(msg));
}

function proxyClose(proxyID) {
    const msg = {
        Type: 'PtyProxyClose',
        Data: {
            SessionId: wsSessionID,
            CustomData: '',
            Data: {
                ProxyId: proxyID,
            },
        }
    };
    console.log(proxyID, 'send PtyProxyClose');
    ws.send(Bson.serialize(msg));
}

const server = Net.createServer(function (socket) {
    const proxyID = `p-${random(10)}`;
    console.log(proxyID, 'new socket connection');

    const eventReady = `${proxyID}#ready`;
    const eventData = `${proxyID}#data`;
    const eventClose = `${proxyID}#close`;

    eventEmitter.on(eventData, (data) => {
        try {
            const d = new Uint8Array(data.buffer);
            socket.write(d);
        } catch (err) {
            console.error(proxyID, 'socket.write get ERROR');
        }
    });

    eventEmitter.on(eventReady, (_) => {
        console.log(proxyID, 'receive PtyProxyReady');
        socket.on('data', (buf) => {
            const data = Array.prototype.slice.call(buf);
            // console.log(proxyID, 'receive socket data, size:', data.length);
            proxyData(proxyID, data);
        });
    });

    eventEmitter.on(eventClose, (_) => {
        console.log(proxyID, 'receive PtyProxyClose');
        remoteClosed = true;
        socket.destroy();
    });

    proxyStart(proxyID, port);

    socket.on('close', () => {
        console.log(proxyID, 'receive socket close');
        proxyClose(proxyID);
        eventEmitter.removeAllListeners(eventReady);
        eventEmitter.removeAllListeners(eventData);
        eventEmitter.removeAllListeners(eventClose);
    });

    socket.on('error', (err) => {
        console.log(proxyID, 'SOCKET ERROR:', err);
    });
});

server.listen(localPort);
