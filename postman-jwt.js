var jwtSecret = pm.environment.get("jwt_secret")

var header = {
	"typ": "JWT",
	"alg": "HS256"
};

var currentTimestamp = Math.floor(Date.now() / 1000)

var data = {
	"iss": pm.environment.get("jwt_issuer"),
	"iat": currentTimestamp,
	"exp": currentTimestamp + pm.environment.get("jwt_expireInSeconds")
}

var additionalClaims = JSON.parse(pm.environment.get("jwt_additionalclaims"))

Object.assign(data, additionalClaims);

var stringifiedHeader = CryptoJS.enc.Utf8.parse(JSON.stringify(header))
var encodedHeader = base64url(stringifiedHeader)

var stringifiedData = CryptoJS.enc.Utf8.parse(JSON.stringify(data))
var encodedData = base64url(stringifiedData)

var token = `${encodedHeader}.${encodedData}`

var signature = CryptoJS.HmacSHA256(token, jwtSecret)
signature = base64url(signature)
var signedToken = `${token}.${signature}`

pm.environment.set("jwt_signed", signedToken)
var jwttoken = signedToken

function base64url(source) {
    encodedSource = CryptoJS.enc.Base64.stringify(source)
    encodedSource = encodedSource.replace(/=+$/, "")
    encodedSource = encodedSource.replace(/\+/g, "-")
    encodedSource = encodedSource.replace(/\//g, "_")
    return encodedSource
}
