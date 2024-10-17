// Datos de inicio de sesión: Arreglo de objetos con usuarios, contraseñas y páginas personalizadas
const usuarios = [
    { username: 'trglixstudios@apple.com', password: '12081986ru', redirectUrl: 'pagina-ruben.html' },
    { username: 'Pablo', password: 'PABLITO2011', redirectUrl: 'pagina-pablo.html' },
    { username: 'admin.web.trglix', password: '12081986ru', redirectUrl: 'pagina-admin.html' },
    { username: 'usuario4', password: 'password4', redirectUrl: 'admin.page' },
    { username: 'usuario5', password: 'password5', redirectUrl: 'pagina-usuario5.html' }
];

// Referencias a elementos del DOM
const loginContainer = document.getElementById('login-container');
const adminPanel = document.getElementById('admin-panel');
const errorMessage = document.getElementById('error-message');
const statusMessage = document.getElementById('status-message');
const welcomeMessage = document.getElementById('welcome-message'); // Referencia al mensaje de bienvenida

// Manejar el inicio de sesión
document.getElementById('login-form').addEventListener('submit', function(event) {
    event.preventDefault();  // Prevenir que el formulario se envíe

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    // Verificar si el usuario y contraseña coinciden
    const usuarioValido = usuarios.find(user => user.username === username && user.password === password);

    if (usuarioValido) {
        // Redirigir a la página personalizada del usuario
        window.location.href = usuarioValido.redirectUrl;
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
    statusMessage.textContent = '';  // Limpiar mensajes de estado

    // Limpiar el formulario de inicio de sesión
    document.getElementById('login-form').reset();
});
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('main-content');

    if (sidebar.classList.contains('closed')) {
        sidebar.classList.remove('closed');
        mainContent.classList.remove('full-width');
    } else {
        sidebar.classList.add('closed');
        mainContent.classList.add('full-width');
    }
}

