
const registerButton = document.getElementById('client--register')
const loginButton = document.getElementById('client--login')
const usernameInput = document.getElementById('email')
const passwordInput = document.getElementById('password')
let isFormFilled = false


const client = new Client()

const initializeClient = () => {
    client.generateKeys()
}

const inputChangeEvent = () => {
    const username = usernameInput.value
    const password = passwordInput.value
    if (username.length > 0 && password.length > 0) {
        registerButton.disabled = false
        loginButton.disabled = false
    } else {
        registerButton.disabled = true
        loginButton.disabled = true
    }
}

const connectViewController = () => {
    usernameInput.onkeydown = function () {
        setTimeout(() => {
            inputChangeEvent()
        }, 10)
    }
    usernameInput.oncut = function () {
        setTimeout(() => {
            inputChangeEvent()
        }, 10)
    }
    usernameInput.onpaste = function () {
        setTimeout(() => {
            inputChangeEvent()
        }, 10)
    }
    passwordInput.onkeydown = function () {
        setTimeout(() => {
            inputChangeEvent()
        }, 10)
    }
    passwordInput.oncut = function () {
        setTimeout(() => {
            inputChangeEvent()
        }, 10)
    }
    passwordInput.onpaste = function () {
        setTimeout(() => {
            inputChangeEvent()
        }, 10)
    }
    registerButton.onclick = function (event) {
        const username = usernameInput.value
        const password = passwordInput.value
    }
    loginButton.onclick = function (event) {
        const username = usernameInput.value
        const password = passwordInput.value
    }
}

window.onload = function (thing) {
    console.log('window loaded')
    console.log(thing)
}
setTimeout(() => {
    console.log(sodium)
}, 100)

function initializeDemo() {
    connectViewController()
}
