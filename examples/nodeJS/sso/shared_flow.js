const Axios = require("axios")
const {
    default: jwtVerify
} = require('jose/jwt/verify')
const {
    default: parseJWK
} = require('jose/jwk/parse')
const {
    parse
} = require("path")
const querystring = require('querystring')

module.exports = {
    params: {
        "response_type": "code",
        "redirect_uri": "https://localhost/callback/",
        "client_id": "ID",
        "scope": "esi-characters.read_blueprints.v1",
        "state": "unique-state",
        "code_challenge": "CHALLENGE",
        "code_challenge_method": "S256"
    },
    headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "login.eveonline.com",
    },
    form_values: {
        "grant_type": "authorization_code",
        "client_id": "client_id",
        "code": "auth_code",
        "code_verifier": "code_verifier"
    },
    createAuthURL(query) {
        const baseURL = `https://login.eveonline.com/v2/oauth/authorize/`
        let fullURL = `${baseURL}&${querystring.stringify(query)}`
        return fullURL.replace("&", "?") // encode the URI and replace the first & with a ?
    },
    async sendTokenRequest(body) {
        console.log(body)
        try {
            const res = await Axios.post("https://login.eveonline.com/v2/oauth/token", body, {
                headers: module.exports.headers
            })
            return res.data
        } catch (e) {
            throw e // pass it to whatever called it
        }
    },
    async validateToken(jwkToken) {
        try {
            const URLs = await module.exports.tokenInfo()
            const jwkURL = URLs.jwks_uri

            // Get the first key that ESI supports
            const res = await Axios.get(jwkURL)
            const keySet = res.data
            const key = keySet.keys.filter(v => v.alg === "RS256")

            // Validate the signature
            const parsedJWK = await parseJWK(jwkToken, "RS256")
            const esiPublicKey = await parseJWK(key)
            const {
                payload,
                protectedHeader
            } = await jwtVerify(jwt, publicKey, {
                issuer: 'login.eveonline.com'
            })
        } catch (e) {
            throw e
        }
    },
    async tokenInfo() {
        try {
            const res = await Axios.get(`https://login.eveonline.com/.well-known/oauth-authorization-server`)
            return res.data
        } catch (e) {
            throw e
        }
    }
}