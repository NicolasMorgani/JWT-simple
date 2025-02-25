const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json()); // Para leer JSON en las solicitudes

const SECRET_KEY = "secreto_super_seguro"; // 🔑 Clave secreta para firmar los tokens

// Ruta para generar el token
app.post("/login", (req, res) => {
    const { username } = req.body;

    if (!username) return res.status(400).json({ message: "Usuario requerido" });

    // Datos que incluirá el JWT (payload)
    const user = { username };

    // Generamos el token que expirará en 1 hora
    const token = jwt.sign(user, SECRET_KEY, { expiresIn: "1h" });

    res.json({ token });
});

// Middleware para verificar el token
const verifyToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    
    if (!authHeader) return res.status(401).json({ message: "Acceso denegado" });

    const token = authHeader.split(" ")[1]; // Extraemos solo el token

    if (!token) return res.status(401).json({ message: "Token no válido" });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ message: "Token inválido" });

        req.user = decoded; // Guardamos los datos del usuario en la solicitud
        next();
    });
};

// Ruta protegida
app.get("/dashboard", verifyToken, (req, res) => {
    res.json({ message: `Bienvenido, ${req.user.username}!` });
});

// Iniciar el servidor
app.listen(3000, () => console.log("Servidor en http://localhost:3000"));
