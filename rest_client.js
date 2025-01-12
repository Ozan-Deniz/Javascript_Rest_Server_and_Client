import axios from 'axios';
import { useUserStore } from '@/stores/userStore';




async function sendMessage(endpoint, method = "GET", body = null){

    //const base_url = import.meta.env.VITE_API_URL;//If you're using Vite, this is a very convenient way to pull server url or ip from .env.development or .env.production files
    const base_url = 'SERVER_URL_HERE example: https://localhost:3000'

    const headers = {"Content-Type": "application/json"};
    
    const options = {
        url: `${base_url}/${endpoint}`,
        method,
        headers,
        withCredentials:true,
    };

    if(body) options.data = body;
    

    try{
        const response = await axios(options);
        
        //alert(JSON.stringify(response));

        if(response.data.type === "tokenExpired"){

            let token_res = await sendMessage("token", "POST");

            if(token_res.type === "refreshAccessSucc"){ 
                return await sendMessage(endpoint, method, body);
             }
             else{
                const userStore = useUserStore();
                userStore.logout();
             }
             
        }
        else if(response.data.type==="noToken"){
            const userStore = useUserStore();
            userStore.logout();
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

export async function guest_register(){
    return await sendMessage("guestregister", "POST");
}

export async function logout(){
    return await sendMessage("logout", "POST");
}

export async function autoLogin(){

    return await sendMessage("token", "POST");
}
