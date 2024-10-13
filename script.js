// Datos de inicio de sesión
const USERNAME = 'ruben.saipol';
const PASSWORD = '12081986ru';

// Referencias a elementos del DOM
const loginContainer = document.getElementById('login-container');
const adminPanel = document.getElementById('admin-panel');
const errorMessage = document.getElementById('error-message');
const statusMessage = document.getElementById('status-message');

// Manejar el inicio de sesión
document.getElementById('login-form').addEventListener('submit', function(event) {
    event.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    if (username === USERNAME && password === PASSWORD) {
        // Ocultar el formulario de inicio de sesión y mostrar el panel de administración
        loginContainer.classList.add('hidden');
        adminPanel.classList.remove('hidden');
        errorMessage.textContent = '';
    } else {
        errorMessage.textContent = 'Usuario o contraseña incorrectos';
    }
});

// Encender servidor
document.getElementById('start-server').addEventListener('click', function() {
    statusMessage.textContent = 'Servidor encendido';
    statusMessage.style.color = 'green';
});

// Apagar servidor
document.getElementById('stop-server').addEventListener('click', function() {
    statusMessage.textContent = 'Servidor apagado';
    statusMessage.style.color = 'red';
});

// Cerrar sesión
document.getElementById('logout').addEventListener('click', function() {
    // Mostrar el formulario de inicio de sesión y ocultar el panel de administración
    loginContainer.classList.remove('hidden');
    adminPanel.classList.add('hidden');
    statusMessage.textContent = '';
    
    // Limpiar el formulario
    document.getElementById('login-form').reset();
});
