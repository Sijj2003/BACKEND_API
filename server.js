require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const cookieParser = require('cookie-parser');
const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const allowedOriginsRegex = /^https:\/\/portalmistic(?:o)?\.vercel\.app$/;

const corsOptions = {
    origin: (origin, callback) => {
        if (!origin || allowedOriginsRegex.test(origin) || origin === 'http://localhost:3000') {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

// Conexión a MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Conectado a MongoDB Atlas'))
  .catch(err => console.error(err));

// Modelo de Usuario
const userSchema = new mongoose.Schema({
    nombre: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    perfil: {
        nombreCompleto: String,
        fechaNacimiento: Date,
        signoZodiacal: String,
        biografia: String,
        telefono: String,
        telegram: String,
        whatsapp: String,
        paisNacimiento: String,
        paisResidencia: String,
        ciudad: String,
        zonaHoraria: String
    }
});
const User = mongoose.model('User', userSchema);

// Modelo de Solicitud de Servicio
const serviceRequestSchema = new mongoose.Schema({
    usuario: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    servicio: { type: String, required: true },
    precio: { type: Number, required: true },
    detalles: { type: String, required: true },
    fechaPreferida: { type: Date, required: true },
    horaPreferida: { type: String, required: true },
    contacto: { type: String, required: true },
    metodoComunicacion: { type: String, required: true },
    metodoPago: { type: String },
    detallesPago: { type: String },
    estado: { type: String, default: 'Pendiente' },
    fechaSolicitud: { type: Date, default: Date.now }
});
const ServiceRequest = mongoose.model('ServiceRequest', serviceRequestSchema);

// Modelo de Soporte
const supportTicketSchema = new mongoose.Schema({
    usuario: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    asunto: { type: String, required: true },
    mensaje: { type: String, required: true },
    contacto: { type: String },
    estado: { type: String, default: 'Abierto' },
    fechaCreacion: { type: Date, default: Date.now },
    respuesta: { type: String },
    fechaRespuesta: { type: Date }
});
const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);

// Modelo de Conversación
const conversationSchema = new mongoose.Schema({
    usuario: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['support', 'consultation'], required: true },
    status: { type: String, enum: ['open', 'closed'], default: 'open' },
    allowUserReply: { type: Boolean, default: true },
    unreadCount: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' }
});
const Conversation = mongoose.model('Conversation', conversationSchema);

// Modelo de Mensaje
const messageSchema = new mongoose.Schema({
    conversation: { type: mongoose.Schema.Types.ObjectId, ref: 'Conversation', required: true },
    senderType: { type: String, enum: ['user', 'admin'], required: true },
    content: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', messageSchema);

// Middleware para verificar token
function verifyToken(req, res, next) {
    const token = req.cookies.token;
    console.log('Token de cookie:', token);

    if (!token) {
        return res.status(401).json({ mensaje: 'Token no proporcionado' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            console.error('Error al verificar token:', err);
            return res.status(401).json({ mensaje: 'Token inválido' });
        }
        req.userId = decoded.userId;
        next();
    });
}

// Middleware para verificar si es administrador
async function verifyAdmin(req, res, next) {
    try {
        const user = await User.findById(req.userId);
        if (!user || user.email !== 'admin@sabiduria2003.com') {
            return res.status(403).json({ mensaje: 'Acceso denegado' });
        }
        next();
    } catch (error) {
        res.status(500).json({ mensaje: 'Error del servidor' });
    }
}

// Función para crear o verificar el usuario administrador
async function ensureAdminExists() {
    try {
        const adminEmail = 'admin@sabiduria2003.com';
        const adminPassword = '31103356';

        // Buscar si el administrador ya existe
        let adminUser = await User.findOne({ email: adminEmail });

        if (!adminUser) {
            // Crear el usuario administrador si no existe
            const hashedPassword = await bcrypt.hash(adminPassword, 10);

            adminUser = new User({
                nombre: 'Administrador',
                email: adminEmail,
                password: hashedPassword
            });

            await adminUser.save();
            console.log('Usuario administrador creado exitosamente');
        } else {
            // Verificar si la contraseña es correcta
            const isPasswordValid = await bcrypt.compare(adminPassword, adminUser.password);
            if (!isPasswordValid) {
                // Actualizar la contraseña si no es correcta
                const hashedPassword = await bcrypt.hash(adminPassword, 10);
                adminUser.password = hashedPassword;
                await adminUser.save();
                console.log('Contraseña de administrador actualizada');
            }
        }
    } catch (error) {
        console.error('Error al asegurar que existe el administrador:', error);
    }
}
// Llamar a la función para asegurar que el administrador existe
ensureAdminExists();

// Ruta principal
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Ruta de Registro
app.post('/api/register', async (req, res) => {
    try {
        const { nombre, email, password } = req.body;

        // Verificar si el usuario ya existe
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ mensaje: 'El email ya está registrado' });

        // Encriptar contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Crear nuevo usuario
        const user = new User({ nombre, email, password: hashedPassword });
        await user.save();

        res.status(201).json({ mensaje: 'Usuario creado exitosamente' });
    } catch (error) {
        res.status(500).json({ mensaje: 'Error en el servidor' });
    }
});

// Ruta de Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        console.log('Intento de login para:', email);

        // Buscar usuario
        const user = await User.findOne({ email });
        if (!user) {
            console.log('Usuario no encontrado:', email);
            return res.status(401).json({ mensaje: 'Credenciales inválidas' });
        }

        // Verificar contraseña
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            console.log('Contraseña inválida para:', email);
            return res.status(401).json({ mensaje: 'Credenciales inválidas' });
        }

        console.log('Login exitoso para:', email);

        // Generar token
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Enviar token en cookie
        const cookieOptions = {
            httpOnly: true,
            maxAge: 3600000,
            secure: isProduction,
            sameSite: isProduction ? 'none' : 'lax'
        };

        res.cookie('token', token, cookieOptions);

        console.log('Token enviado en cookie');

        // Verificar si es el administrador
        if (email === 'admin@sabiduria2003.com') {
            console.log('Redirigiendo al panel de administración');
            res.json({
                nombre: user.nombre,
                isAdmin: true,
                redirect: '/admin.html'
            });
        } else {
            console.log('Redirigiendo al dashboard de usuario');
            res.json({
                nombre: user.nombre,
                isAdmin: false,
                redirect: '/dashboard.html'
            });
        }
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ mensaje: 'Error en el servidor' });
    }
});

// Ruta protegida para el dashboard
app.get('/dashboard', verifyToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Ruta para el dashboard de administrador
app.get('/admin', verifyToken, verifyAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Ruta para obtener datos del usuario
app.get('/api/user', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password');
        res.json(user);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener datos del usuario' });
    }
});

// Ruta para cerrar sesión
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/index.html');
});

// Ruta para actualizar perfil
app.put('/api/profile', verifyToken, async (req, res) => {
    try {
        const updatedUser = await User.findByIdAndUpdate(
            req.userId,
            { $set: { perfil: req.body } },
            { new: true }
        ).select('-password');

        res.json(updatedUser);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al actualizar perfil' });
    }
});

// Ruta para la página de perfil
app.get('/profile', verifyToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

// Ruta para crear solicitud de servicio
app.post('/api/services', verifyToken, async (req, res) => {
    try {
        console.log('Datos recibidos:', req.body);
        const { servicio, precio, detalles, fechaPreferida, horaPreferida, contacto, metodoComunicacion } = req.body;

        // Validar que todos los campos requeridos estén presentes
        if (!servicio || !precio || !detalles || !fechaPreferida || !horaPreferida || !contacto || !metodoComunicacion) {
            return res.status(400).json({ mensaje: 'Faltan campos requeridos' });
        }

        // Convertir fechaPreferida a objeto Date
        const fecha = new Date(fechaPreferida);
        if (isNaN(fecha.getTime())) {
            return res.status(400).json({ mensaje: 'Fecha inválida' });
        }

        const newRequest = new ServiceRequest({
            usuario: req.userId,
            servicio,
            precio,
            detalles,
            fechaPreferida: fecha,
            horaPreferida,
            contacto,
            metodoComunicacion
        });

        await newRequest.save();

        console.log('Solicitud guardada:', newRequest);

        res.status(201).json({ mensaje: 'Solicitud creada correctamente', solicitud: newRequest });
    } catch (error) {
        console.error('Error al crear solicitud:', error);
        res.status(500).json({ mensaje: 'Error al crear solicitud', error: error.message });
    }
});

// Ruta para obtener solicitudes del usuario
app.get('/api/services', verifyToken, async (req, res) => {
    try {
        const requests = await ServiceRequest.find({ usuario: req.userId })
            .sort({ fechaSolicitud: -1 });
        res.json(requests);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener solicitudes' });
    }
});

// Ruta para eliminar una solicitud de servicio
app.delete('/api/services/:id', verifyToken, async (req, res) => {
    try {
        const service = await ServiceRequest.findOne({ _id: req.params.id, usuario: req.userId });

        if (!service) {
            return res.status(404).json({ mensaje: 'Solicitud no encontrada' });
        }

        await ServiceRequest.deleteOne({ _id: req.params.id, usuario: req.userId });
        res.json({ mensaje: 'Solicitud eliminada exitosamente' });
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al eliminar solicitud' });
    }
});

// Ruta para el dashboard de administración
app.get('/admin-dashboard', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const totalServices = await ServiceRequest.countDocuments();
        const pendingServices = await ServiceRequest.countDocuments({ estado: 'Pendiente' });
        res.json({ totalUsers, totalServices, pendingServices });
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener datos del dashboard de admin' });
    }
});

// Ruta para obtener todas las solicitudes de servicio (solo admin)
app.get('/api/admin/services', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const services = await ServiceRequest.find().sort({ fechaSolicitud: -1 });
        res.json(services);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener servicios para admin' });
    }
});

// Ruta para cambiar el estado de una solicitud (solo admin)
app.put('/api/admin/services/:id/status', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { estado } = req.body;
        const updatedService = await ServiceRequest.findByIdAndUpdate(
            req.params.id,
            { estado },
            { new: true }
        );

        if (!updatedService) {
            return res.status(404).json({ mensaje: 'Solicitud no encontrada' });
        }

        res.json(updatedService);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al actualizar estado de solicitud' });
    }
});

// Nuevas rutas para soporte y conversaciones
app.post('/api/support/create', verifyToken, async (req, res) => {
    try {
        const { asunto, mensaje, contacto } = req.body;
        const newTicket = new SupportTicket({
            usuario: req.userId,
            asunto,
            mensaje,
            contacto
        });
        await newTicket.save();
        res.status(201).json({ mensaje: 'Ticket de soporte creado exitosamente' });
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al crear ticket de soporte' });
    }
});

app.get('/api/support/tickets', verifyToken, async (req, res) => {
    try {
        const tickets = await SupportTicket.find({ usuario: req.userId }).sort({ fechaCreacion: -1 });
        res.json(tickets);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener tickets de soporte' });
    }
});

app.post('/api/conversations/start', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { userId, initialMessage, type } = req.body;

        if (!userId || !initialMessage || !type) {
            return res.status(400).json({ mensaje: 'Faltan campos requeridos' });
        }

        // Verificar que el usuario exista
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ mensaje: 'Usuario no encontrado' });
        }

        // Crear nueva conversación
        const newConversation = new Conversation({
            usuario: userId,
            type,
            status: 'open',
            allowUserReply: true
        });

        await newConversation.save();

        // Crear mensaje inicial
        const newMessage = new Message({
            conversation: newConversation._id,
            senderType: 'admin',
            content: initialMessage.trim()
        });

        await newMessage.save();

        // Actualizar último mensaje
        newConversation.lastMessage = newMessage._id;
        await newConversation.save();

        res.status(201).json({
            mensaje: 'Conversación creada correctamente',
            conversation: newConversation
        });
    } catch (error) {
        console.error('Error al crear conversación:', error);
        res.status(500).json({ mensaje: 'Error al crear conversación' });
    }
});

// Ruta para el favicon
app.get('/favicon.ico', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'favicon.ico'));
});

// Iniciar servidor
app.listen(process.env.PORT, () => {
    console.log(`Servidor corriendo en puerto ${process.env.PORT}`);
});
