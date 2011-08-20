

var InvalidFbSignedRequestError = function(msg) {
	  this.message = msg;
	  Error.call(this, msg);
	  Error.captureStackTrace(this, arguments.callee);
}
InvalidFbSignedRequestError.prototype.__proto__ = Error.prototype;


var parseSignedRequest = function(signedReq, verify, facebookSecret) {
    if (!signedReq) {
        throw new InvalidFbSignedRequestError('No signed request passed');
    }

    var parts = signedReq.split('.');
    if (!parts || !parts[1]) {
        throw new InvalidFbSignedRequestError('Signed request can not be parsed: no parts');
    }

    var sig = base64UrlToBase64(parts[0]);
    var payload = parts[1];

    var data = null;
    try {
        data = JSON.parse(base64UrlToStr(payload));
    } catch(e) {
        throw new InvalidFbSignedRequestError('Invalid Json syntax');
    }

    if (verify) {
	    if (data.user_id) {
	        if (data.algorithm.toUpperCase() !== 'HMAC-SHA256') {
	            throw new InvalidFbSignedRequestError('Unknown algorithm. Expected HMAC-SHA256');
	        }
	
	        var hmac = require('crypto').createHmac('sha256', facebookSecret);
	        hmac.update(payload);
	        var expectedSig = hmac.digest('base64');
	
	        if (sig != expectedSig) {
	            throw new InvalidFbSignedRequestError('Expected different signature');
	        }
	    }
    }

    return data;
}


function extend(obj) {
	var newObj = obj;
	
    Array.prototype.slice.call(arguments).forEach(function(source) {
    	for (var prop in source) newObj[prop] = source[prop];
    });
    return newObj;
};


var base64ToStr = function(str) {
	return (new Buffer(str || "", "base64")).toString("ascii");
};

var base64UrlToStr = function(str) {
    return base64ToStr(base64UrlToBase64(str));
};

var base64UrlToBase64 = function(str) {
    var paddingNeeded = (4- (str.length%4));
    for (var i = 0; i < paddingNeeded; i++) {
        str = str + '=';
    }
    return str.replace(/\-/g, '+').replace(/_/g, '/')
};


module.exports = new function() {
    this.create = function(userSettings) {
        return new function() {
            var defaultSettings = {
                verify: true,
                secret: ''
            };

            var settings = extend(defaultSettings, userSettings);
            if (!settings.secret) settings.secret = '';

            console.log(settings);

            this.parse = function(signedRequest) {
                return parseSignedRequest(signedRequest, settings.verify, settings.secret);
            }
        }
    };

    this.InvalidFbSignedRequestError = InvalidFbSignedRequestError;
}
