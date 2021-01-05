const Inquirer = require('inquirer')
const Chalk = require('chalk')
const crypto = require('crypto') // For the generation and hashing
const querystring = require('querystring')
const {
    createAuthURL,
    sendTokenRequest,
    params,
    form_values,
    validateToken
} = require('./shared_flow')

// Prepare questions
const questions = [{
        type: 'input',
        name: 'clientID',
        message: `Copy your SSO application's client ID and enter it here:`,
        validate: (input) => {
            if (input === '') {
                return "Please enter a client ID."
            }
            return true
        }
    },
    {
        type: 'confirm',
        name: 'confirm',
        message: `Press Enter to continue:`,
        default: true
    },
    {
        type: 'input',
        name: 'code',
        message: `Copy the "code" query parameter and enter it here:`,
        validate: (input) => {
            if (input === '') {
                return "Please enter the code."
            }
            return true
        }
    }
]
// Start program
async function start() {
    // create the challenge
    const codeChallenge = await crypto.randomBytes(32).toString('base64')
    // ^ Create the 32 byte string in base64...
    const hashedCodeChallenge = await crypto.createHash('sha256')
    await hashedCodeChallenge.update(codeChallenge)
    const digestedHash = await hashedCodeChallenge.digest('base64').replace("=", "")
    // ^ ...hash it, and save the digest

    // now start the program
    // Grab the client ID...
    console.log(`This program will take you through an example OAuth 2.0 flow that you should be using if you are building a desktop or mobile application. Follow the prompts and enter the info asked for.`)
    const questionOne = await Inquirer.prompt(questions[0])
    const clientID = questionOne.clientID

    // ...generate the URL...
    console.log(`\nBecause this is a desktop/mobile application, you should use the PKCE protocol when contacting the EVE SSO. In this case, that means sending a base 64 encoded sha256 hashed 32 byte string called a code challenge. This 32 byte string should be ephemeral and never stored anywhere. The code challenge string generated for this program is ${Chalk.yellowBright(codeChallenge)} and the hashed code challenge is ${Chalk.yellowBright(digestedHash)}.`)
    console.log(`Notice that the query parameter of the following URL will contain this code challenge.\n`)
    await Inquirer.prompt(questions[1]) // no "const" since input isn't needed

    // create the parameters...
    let query = params
    query.client_id = clientID
    query.code_challenge = digestedHash
    console.log(`\nOpen the following link in your browser:\n`)
    // ...display the url...
    const authURL = await createAuthURL(query)
    console.log(` ${Chalk.green(authURL)}\n`)
    console.log(` Once you have logged in as a character you will get redirected to ${Chalk.yellowBright("https://localhost/callback/.")}`)

    // ...prompt for the code...
    const questionThree = await Inquirer.prompt(questions[2])
    const code = questionThree.code

    // ...and send the request...
    let form = form_values
    form.code = code
    form.client_id = clientID
    form.code_verifier = codeChallenge

    const res = await sendTokenRequest(querystring.stringify(form))
    const token = await validateToken(res)
    console.log(`\nThe contents of the access token are: ${JSON.stringify(token, null, 2)}`)
}
start().catch(e => {
    console.error(e.response.data || e.stack)
    process.exit()
})