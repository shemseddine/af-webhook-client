var restify = require('restify');
var crypto = require("crypto");

var secret = "secret";

const server = restify.createServer({
  name: 'myapp',
  version: '1.0.0'
});

server.use(restify.plugins.acceptParser(server.acceptable));
server.use(restify.plugins.queryParser());
server.use(restify.plugins.bodyParser());

server.post('/webhooks', function (req, res, next) {
    var signature = req.header("x-hub-signature");
    var eventType = req.header("x-event-type")

    var hashed = getSignature(req.body, secret);

    var validSignature = crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(hashed));

    if (signature && validSignature) {
        if (eventType === "document_uploaded") {
            console.log("received document_uploaded event: ", req.body);
        }
        
        res.send(req.params);
        return next();
    } else {
        res.send(401, "unathorised");
    }
});

server.listen(8080, function () {
  console.log('%s listening at %s', server.name, server.url);
});

getSignature = (payload, key) => {
    var sha1Prefix = "sha1=";
    var encoded  = new Buffer.from(JSON.stringify(payload), "ascii");
    return sha1Prefix + crypto.createHmac("sha1", key).update(encoded).digest("hex");
}