
class Server {

    constructor (serverId) {
        this.serverId = serverId
        this.clients = {}
    }

    createRegistrationResponse(registrationRequest) {
        this.clients[registrationRequest.username] = {

        }
    }
}

exports.Server = Server
