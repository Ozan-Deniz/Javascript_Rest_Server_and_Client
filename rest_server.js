//Core libraries
const https = require('https');
const fs = require('fs');
const express = require('express');
const {Pool} = require('pg');

//middleware and utilities
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const cookieParser = require('cookie-parser');

//Security and encryption
const bcrypt = require('bcrypt');
const saltRounds = 12; // The cost factor determines the complexity of the hashing process
const jwt = require('jsonwebtoken');

//Environment variables
require('dotenv').config();
const PORT = 3000;



const app = express();
app.use(cors({credentials:true, origin: 'http://localhost:5173',}));
//app.use(cors({credentials:true}));
app.use(express.json());
app.use(cookieParser());


const email_regex = new RegExp("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
const password_regex = /^[^\s]{8,64}$/;

const guestRegisterLimiter = rateLimit( {
    windowMs : 10000,// 10.000 ms = 10 seconds
    max:1,
    message:"Too many guest register requests. Please try again later."
}); 

const options = {
    key: fs.readFileSync('./key.pem'),
    cert: fs.readFileSync('./cert.pem')
};

const db = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASS,
    port: process.env.DB_PORT, // default port for PostgreSQL
});

db.connect().then(()=>{
    console.log("Connected to the database.");
}).catch(err=>{
    console.error("Database connection error: ", err.stack);
});




app.get('/', (req, res) => {
    res.json(getMessage("Server is running!"));
});

const loginHandler = async (req, res)=>{
    
    let {username, password} = req.body;

    if (!username || !password) {

        return res.json(getMessage("missingCred")); // Missing credentials
    }
    username=username.toLowerCase();

    const result = await db.query('SELECT id, token_version, password FROM auth WHERE username = $1' ,
        [username]
    );
    if(result.rowCount===0){
        return res.json(getMessage("WrongCred"));//wrong credentials
    }

    let row = result.rows[0];
    
    const passMatched = await bcrypt.compare(password, row.password);

    if(!passMatched)return res.json(getMessage("WrongCred"));

    let r = getMessage("loginSucc");

    let token_version = Number(row.token_version);
    let refresh_token = generateRefreshToken(r.id, token_version);

    addRefreshCookie(res,refresh_token);

    r.username = username;
    return res.json(r);
};

const logoutHandler = async (req, res, access_payload)=>{
    removeAccessToken(res);
    const refresh_token = req.cookies.refresh_token;
    removeRefreshToken(res);
    if(!req.cookies.refresh_token){
        return res.json(getMessage("logoutFail")); 
    }

    const secret = process.env.JWT_REFRESH_SECRET;
    const payload = jwt.verify(refresh_token, secret);

    
    if (payload.userid == null || payload.version == null) {
        return res.json(getMessage("logoutFail"));
    }

    db.query('UPDATE auth SET token_version = token_version + 1 WHERE id = $1 AND token_version = $2' ,
        [payload.userid, payload.version]
    );


    return res.json(getMessage("logoutSucc"));
};

const registerHandler = async (req,res)=>{

    let {username, password} = req.body;
    if(!username)throw new Error("Username cannot be empty.");
    if(!password)throw new Error("Password cannot be empty.");

    if(!email_regex.test(username)){throw new Error("Invalid email.");}
    if(!password_regex.test(password)){throw new Error("Invalid password.");}

    username=username.toLowerCase();
    password = await hash_pass(password);
    
    const result = await db.query('SELECT * FROM auth WHERE username = $1',[username]);
    
    
    if(result.rowCount!==0){
        return res.json(getMessage("UserExists"));
    }
   
    await db.query('INSERT INTO auth (username, password) VALUES ($1, $2)',[username,password]);
    return res.json(getMessage("RegisterSucc"));
}
const generateRefreshToken = (userid, version) => {
    const payload = {
        userid,
        version
    };

    const secret = process.env.JWT_REFRESH_SECRET;
    const options={
        expiresIn: process.env.JWT_REFRESH_EXPIRES || "99y",
    };


    return jwt.sign(payload,secret, options);
}

const generateAccessToken = (userid) => {
    const payload = {
        userid
    };

    const secret = process.env.JWT_ACCESS_SECRET;
    const options={
        expiresIn: process.env.JWT_ACCESS_EXPIRES || "15m",
    };

    return jwt.sign(payload,secret, options);

}




const refreshAccessTokenHandler = async (req, res)=>{
    
    let refresh_token = req.cookies.refresh_token;
    if(!refresh_token){return res.json(getMessage("refreshAccessFail"));}

    const secret = process.env.JWT_REFRESH_SECRET;
    try{
        const payload = jwt.verify(refresh_token, secret);
        console.log("Payload : "+JSON.stringify(payload));

        if (payload.userid == null || payload.version == null){
            removeRefreshToken(res);
            return res.json(getMessage("refreshAccessFail"));
        }
        
        const result = await db.query('SELECT username, token_version FROM auth WHERE id = $1',[payload.userid]);
        
        if(result.rowCount===0){

            removeRefreshToken(res);
            return res.json(getMessage("refreshAccessFail"));
        }

        let row = result.rows[0];

        if(payload.version !== row.token_version){
            removeRefreshToken(res);
            return res.json(getMessage("refreshAccessFail"));
        }
        let access_token = generateAccessToken(payload.userid);

        addAccessToken(res,access_token);
        
        let r = getMessage("refreshAccessSucc");
        r.username = row.username;
        return res.json(r);

    }
    catch(err){
        removeRefreshToken(res);
        return res.json(getMessage("autoLoginFail"));
    }
    
        
};

const isProduction = () => process.env.NODE_ENV === 'production';


const guestRegisterHandler = async (req,res)=>{
    guestRegisterLimiter(req, res, async  () => {

        const result = await db.query('INSERT INTO auth DEFAULT VALUES RETURNING id, token_version');

        const { id, token_version } = result.rows[0];

        const refresh_token = generateRefreshToken(id,token_version);
        console.log("guestRegisterHandler:refresh_token: "+refresh_token);

        addRefreshCookie(res,refresh_token);
        

        return res.json(getMessage("guestRegisterSucc"));
    });
}

const hash_pass = async (pass)=>{

    try{
        return await bcrypt.hash(pass, saltRounds);
    }
    catch(error){
        throw new Error("Error while hashing the password.");
    }
}

const getMessage = (message_type)=>{
    return {type:message_type};
}

const getError = (error_info) =>{
    return {type:"error", info:error_info};
}

const addRefreshCookie = (res, token) => {
    res.cookie('refresh_token', token, {
        httpOnly: true, // Cannot be accessed by JavaScript (prevents XSS)
        secure: true, // Only send over HTTPS in production
        maxAge: 3650 * 1000 * 60 * 60 * 24, // Expires in 10 years (also expires on logout)
        sameSite: isProduction() ? 'Strict' : 'None', // Helps prevent CSRF attacks
    });
}

const addAccessToken = (res, token) => {
    res.cookie('access_token', token, {
        httpOnly: true, // Cannot be accessed by JavaScript (prevents XSS)
        secure: true, // Only send over HTTPS in production
        maxAge: 1000 * 60 * 15, // Expires in 15 minutes (also expires on logout)
        sameSite: isProduction() ? 'Strict' : 'None', // Helps prevent CSRF attacks
    });
}

const removeAccessToken = (res) => {
    res.clearCookie('access_token', {
        httpOnly: true,
        secure: true,
        sameSite: isProduction() ? 'Strict' : 'None',
    });
}

const removeRefreshToken = (res) => {
    res.clearCookie('refresh_token', {
        httpOnly: true, // Make sure to include the same options as when you set the cookie
        secure: true, // Must match the cookie's secure setting
        sameSite: isProduction() ? 'Strict' : 'None', // Helps prevent CSRF attacks
    });
}

routes={
    "/login": {GET:null, POST:loginHandler, authNeeded:false},
    "/register": {GET:null, POST:registerHandler, authNeeded:false},
    "/logout" : {GET:null, POST:logoutHandler, authNeeded:true},
    "/token" : {GET:null, POST:refreshAccessTokenHandler, authNeeded:false},
    "/guestregister" : {GET:null, POST:guestRegisterHandler, authNeeded:false}
}

app.all("/*", (req,res)=>{
    try{
        const {method, path} = req;

        const handler = routes[path] && routes[path][method];
        if(handler){
            console.log("Handling "+path);
            if(routes[path].authNeeded){
                let access_token = req.cookies.access_token;
                let refresh_token = req.cookies.refresh_token;
                if(!refresh_token)return res.json(getMessage("noToken"));
                else if(!access_token) return res.json(getMessage("tokenExpired"));
                
                const secret = process.env.JWT_ACCESS_SECRET;
                try{
                    const payload = jwt.verify(access_token, secret);
                    return handler(req,res, payload);
                }
                catch(error){
                    removeAccessToken();
                    return res.json(getMessage("tokenExpired"));
                }


            }
            else return handler(req,res);
        }
        else{
            return res.status(404).json(getError("Wrong path or method."));
        }
    }   
    catch(error){
        if(error.status===429){
            return res.json(getMessage("TooManyRequests"));
        }
        return res.json(getError(error.message));
    }
});

https.createServer(options, app).listen(PORT, () => {
    console.log(`Server running on https://localhost:${PORT}`);
});
