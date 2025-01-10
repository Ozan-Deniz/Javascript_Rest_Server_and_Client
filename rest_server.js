const express = require('express');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const {Pool} = require('pg');
const bcrypt = require('bcrypt');
const saltRounds = 12; // The cost factor determines the complexity of the hashing process
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());
app.use(cookieParser());

const PORT = 3000;

const email_regex = new RegExp("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
const password_regex = /^[^\s]{8,64}$/;



const guestRegisterLimiter = rateLimit( {
    windowMs : 10000,// 10.000 ms = 10 seconds
    max:1,
    message:"Too many guest register requests. Please try again later."
}); 



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

        return res.status(400).json(getMessage("missingCred")); // Missing credentials
    }
    username=username.toLowerCase();

    const query = 'SELECT id, token_version, password FROM auth WHERE username = $1';
    const values = [username];
    const result = await db.query(query,values);
    if(result.rowCount===0){
        return res.json(getMessage("WrongCred"));//wrong credentials
    }

    let row = result.rows[0];
    
    const passMatched = await bcrypt.compare(password, row.password);

    if(!passMatched)return res.json(getMessage("WrongCred"));

    let r = getMessage("loginSucc");

    let token_version = Number(row.token_version);
    let refresh_token = generateRefreshToken(r.id, token_version);

    res.cookie('refresh_token', refresh_token, {
        httpOnly: true, // Cannot be accessed by JavaScript (prevents XSS)
        secure: process.env.NODE_ENV === 'production', // Only send over HTTPS in production
        maxAge: 3650 * 1000 * 60 * 60 * 24, // Expires in 10 years (also expires on logout)
        sameSite: 'Strict' // Helps prevent CSRF attacks
    });

    r.username = username;
    return res.json(r);
};
    const logoutHandler = async (req, res, access_payload)=>{
    
    if(!req.cookies.refresh_token){

        return res.json(getMessage("logoutFail")); 
    }

    const secret = process.env.JWT_REFRESH_SECRET;
    const payload = jwt.verify(req.cookies.refresh_token, secret);
    if (!payload.userid || !payload.version) {
        return res.json(getMessage("logoutFail"));
    }



    const query = 'UPDATE auth SET token_version = token_version + 1 WHERE id = $1 AND token_version = $2';
    const values = [payload.userid, payload.version];
    db.query(query,values);

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
    const query = 'SELECT * FROM auth WHERE username = $1';
    const values = [username];
    const result = await db.query(query,values);
    if(result.rowCount!==0){
        return res.json(getMessage("UserExists"));
    }
    const reg_query = 'INSERT INTO auth (username, password) VALUES ($1, $2)';
    const reg_values = [username,password];

    await db.query(reg_query,reg_values);
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
    if(!refresh_token){return res.status(401).json(getMessage("refreshAccessFail"));}



    const secret = process.env.JWT_REFRESH_SECRET;
    try{
        const payload = jwt.verify(refresh_token, secret);
        if (!payload.userid || !payload.version) return res.status(401).json(getMessage("refreshAccessFail"));
        const query = 'SELECT username, token_version FROM auth WHERE id = $1';
        const values = [payload.userid];
        const result = await db.query(query,values);
        if(result.rowCount===0){
            return res.status(401).json(getMessage("refreshAccessFail"));
        }

        let row = result.rows[0];

        if(payload.token_version !== row.token_version) return res.status(401).json(getMessage("refreshAccessFail"));

        let access_token = generateAccessToken(payload.userid);

        res.cookie('access_token', access_token, {
            httpOnly: true, // Cannot be accessed by JavaScript (prevents XSS)
            secure: process.env.NODE_ENV === 'production', // Only send over HTTPS in production
            maxAge: 1000 * 60 * 15, // Expires in 15 minutes (also expires on logout)
            sameSite: 'Strict' // Helps prevent CSRF attacks
        });
        let r = getMessage("refreshAccessSucc   ");
        r.username = row.username;
        return res.json(r);

    }
    catch(err){
        return res.status(401).json(getMessage("autoLoginFail"));
    }
    
        
};


const guestRegisterHandler = (req,res)=>{
    loginRegisterLimiter(req, res, () => {
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
routes={
    "/login": {GET:null, POST:loginHandler, authNeeded:false},
    "/register": {GET:null, POST:registerHandler, authNeeded:false},
    "/logout" : {GET:null, POST:logoutHandler, authNeeded:true},
    "/token" : {GET:null, POST:refreshAccessTokenHandler, authNeeded:false}
}

app.all("/*", (req,res)=>{
    try{
        const {method, path} = req;

        const handler = routes[path] && routes[path][method];
        if(handler){

            if(routes[path].authNeeded){
                let access_token = req.cookies.access_token;
                let refresh_token = req.cookies.refresh_token;
                if(!refresh_token)return res.status(401).json(getMessage("noToken"));
                else if(!access_token) return res.status(401).json(getMessage("tokenExpired"));
                
                const secret = process.env.JWT_ACCESS_SECRET;
                try{
                    const payload = jwt.verify(access_token, secret);
                    handler(req,res, payload);
                }
                catch(error){
                    res.clearCookie('access_token', {
                        httpOnly: true, // Make sure to include the same options as when you set the cookie
                        secure: process.env.NODE_ENV === 'production', // Must match the cookie's secure setting
                        sameSite: 'Strict' // Must match the cookie's SameSite setting
                    });
                    return res.status(401).json(getMessage("tokenExpired"));
                }


            }
            else handler(req,res);
        }
        else{
            res.status(404).json(getError("Wrong path or method."));
        }
    }   
    catch(error){
        res.status(500).json(getError(error.message));
    }
});

app.listen(PORT, ()=>{
    console.log(`Server is running on http://localhost:${PORT}`);
});
