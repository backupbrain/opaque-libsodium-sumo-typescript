
class Client {

    constructor (username) {
        this.username = username
    }

    createBlindPassword (password) {
        const blindPassword = Buffer.from(password, 'utf8')
        return blindPassword
    }

    createRegistrationRequest (password, key) {
        const blindPassword = this.createBlindPassword(password)
        const output = {
            username: this.username,
            blindPassword: blindPassword
        }
        return output
    }
}

exports.Client = Client
