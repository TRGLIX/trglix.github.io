/* Estilos generales */
body {
    margin: 0;
    font-family: 'Roboto', sans-serif;
    background-image: url('tu-imagen-de-fondo-body.jpg'); /* Imagen de fondo para todo el body */
    background-size: cover;
    background-position: center;
    background-repeat: no-repeat;
    background-attachment: fixed;
    color: white; /* Cambia el color del texto a blanco para mejor visibilidad */
    display: flex;
    justify-content: center; /* Centra horizontalmente */
    align-items: center; /* Centra verticalmente */
    height: 100vh; /* Hace que el body ocupe toda la altura de la ventana */
}

/* Lista de archivos */
.file-list {
    background-color: rgba(44, 62, 80, 0.8); /* Fondo semitransparente para destacar la lista */
    padding: 20px;
    border-radius: 10px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
}

.file-list ul {
    list-style: none;
    padding: 0;
}

.file-list ul li {
    padding: 10px;
    text-align: center;
}

.file-list ul li a {
    color: white;
    text-decoration: none;
    font-size: 18px;
    display: block;
    padding: 10px;
    background-color: rgba(0, 0, 0, 0.4);
    border-radius: 5px;
    transition: background-color 0.3s ease;
}

.file-list ul li a:hover {
    background-color: rgba(0, 0, 0, 0.6); /* Cambia el fondo al pasar el mouse */
}
