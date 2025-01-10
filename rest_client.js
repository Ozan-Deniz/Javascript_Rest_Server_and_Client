import axios from 'axios';



async function sendMessage(endpoint, method = "GET", body = null){

    //const base_url = import.meta.env.VITE_API_URL;//If you're using Vite, this is a very convenient way to pull server url or ip from .env.development or .env.production files
    const base_url = 'SERVER_URL_HERE example: localhost:3000'
    const headers = {"Content-Type": "application/json"};
    
    const options = {
        url: `${base_url}/${endpoint}`,
        method,
        headers
    };

    if(body) options.data = body;
    

    try{
        const response = await axios(options);


        if(response.data.type === "tokenExpired"){
            let token_res = await sendMessage("token", "POST");

            if(token_res.type === "refreshAccessSucc"){ 
                return await sendMessage(endpoint, method, body);
             }
             else{
                //redirect to login page
             }
             
        }

        return response.data;

    }
    catch(error){
        return {type:"error", data:error.message};
    }   
}

export async function login(email, pass){

    return await sendMessage("login", "POST", {username:email, password:pass});

}

export async function register(email, pass){
    return await sendMessage("register", "POST", {username:email, password:pass});
}


export async function logout(){
    return await sendMessage("logout", "POST");
}
