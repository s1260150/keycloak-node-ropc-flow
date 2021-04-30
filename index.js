const express = require('express');
const session = require('express-session');
const axios = require('axios');
const qs = require('qs');
const jwt_decode = require('jwt-decode');

const app = express();

app.set('view engine', 'pug');
app.set('views', require('path').join(__dirname, '/views'));

app.use(express.json())
    .use(express.urlencoded({ extended: true }));

const memoryStore = new session.MemoryStore();
app.use( session(
{
    secret: 'secret',
    resave: false,
    saveUninitialized: true,
    store: memoryStore,
    cookie:
    {
        httpOnly: true,
    }
}));


//ユーザ管理用 ( ユーザの参照、登録や削除など ) のトークンを管理します
class TokenManager
{
    constructor()
    {
        this.access_token = null;
        this.refresh_token = null;
        this.refresh_time = null;
        this.access_time = null;
        this.expires_in = null;
        this.refresh_expires_in = null;
    }

    async init_token()
    {
        const body = 
        {
            grant_type: 'password',
            client_id: 'admin-cli',
            username: 'admin',
            password: 'admin',
        }

        const axiosConfig = { headers: { } };

        const response = await axios.post('http://localhost:8080/auth/realms/master/protocol/openid-connect/token', qs.stringify(body), axiosConfig);

        this.access_token = response.data.access_token;
        this.refresh_token = response.data.refresh_token;
        this.expires_in = response.data.expires_in;
        this.refresh_expires_in = response.data.refresh_expires_in;

        this.refresh_time = this.access_time = Date.now();
        
        console.log('get tokens');
    }

    async refresh()
    {
        const body = 
        {
            grant_type: 'refresh_token',
            client_id: 'admin-cli',
            refresh_token: this.refresh_token,
        }

        const axiosConfig = { headers: { } };
    
        const response = await axios.post('http://localhost:8080/auth/realms/master/protocol/openid-connect/token', qs.stringify(body), axiosConfig);

        this.access_token = response.data.access_token;

        this.access_time = Date.now();

        console.log('refreshed access token');
    }

    async get_token()
    {
        if(!this.access_token) return null;

        const now = Date.now();

        if(Math.floor((now - this.access_time) / 1000) > Math.floor(this.expires_in / 2))
        {
            if(Math.floor((now - this.refresh_time) / 1000) > Math.floor(this.refresh_expires_in / 2))
            {
                return null;
            }

            await this.refresh();
        }

        return this.access_token;
    }
};
const token_manager = new TokenManager();


/*
    以下、リソースオーナーパスワードクレデンシャルズフローを利用したユーザ認証
*/

app.use(async (req, res, next) =>
{
    console.log(`request to "${req.url}"`);

    //管理用のトークンが有効でない場合は、新たにトークンを取得する
    if(!await token_manager.get_token())
    {
        try
        {
            await token_manager.init_token();
        }
        catch(err)
        {
            console.log('管理アカウントの認証に失敗しました');
            console.log(err.response?.data);
            console.log(err.response?.status);
            console.log(err.response?.statusText);
            res.status(500).send();

            return;
        }
    }


    const access_token = req.session.access_token;
    if(req.url.indexOf("/login") > -1 || req.url.indexOf("/register") > -1 || access_token)
    {
        next();
    }
    else
    {
        res.redirect('/login');
    }
});

app.get('/', (req, res) =>
{
    res.render('index', 
    {
        access_token: req.session.access_token,
        refresh_token: req.session.refresh_token,
        id_token: req.session.id_token,
        decoded_access_token: jwt_decode(req.session.access_token),
        decoded_refresh_token: jwt_decode(req.session.refresh_token),
        decoded_id_token: jwt_decode(req.session.id_token),
    });
});

app.get('/login', (req, res)　=>
{
    res.render('login');
})

app.post('/login', async (req, res)　=>
{
    const username = req.body.username;
    const password = req.body.password;

    const body = 
    {
        grant_type: 'password',
        scope: 'openid profile',
        client_id: 'js-console',
        client_secret: 'eb261cff-5580-4b50-8806-980794d77f76',
        username: username,
        password: password,
    }

    try
    {
        console.log('login 要求', body);
    
        const axiosConfig = { headers: { } };
    
        const response = await axios.post('http://localhost:8080/auth/realms/ROPC/protocol/openid-connect/token', qs.stringify(body), axiosConfig);
    
        console.log(response.data);
    
        const access_token = response.data.access_token;
        const refresh_token = response.data.refresh_token;
        const id_token = response.data.id_token;
    
        req.session.access_token = access_token;
        req.session.refresh_token = refresh_token;
        req.session.id_token = id_token;
    
        res.status(200).send();
    }
    catch(err)
    {
        console.log(err.response.data);
        console.log(err.response.status);
        console.log(err.response.statusText);

        res.status(err.response.status).json(
        {
            error: err.response.data.error,
            error_description: err.response.data.error_description,
            status: err.response.status,
            status_text: err.response.statusText,
        });
    }
})

app.get('/register', (req, res)　=>
{
    res.render('register');
})

app.post('/register', async (req, res)　=>
{
    const username = req.body.username;
    const password = req.body.password;
    const firstname = req.body.firstname;
    const lastname = req.body.lastname;

    try
    {
        console.log('register 要求');
    
        const data = 
        {
            username,
            enabled: true,
            firstName: firstname,
            lastName: lastname,
            credentials: [ { "type": "password", "value": password, "temporary": false } ]
        };

        const axiosConfig = { headers: { Authorization: `Bearer ${await token_manager.get_token()}` } };

        const response = await axios.post('http://localhost:8080/auth/admin/realms/ROPC/users', data, axiosConfig);
    
        res.status(response.status).send();
    }
    catch(err)
    {
        console.log(err.response?.data);
        console.log(err.response?.status);
        console.log(err.response?.statusText);

        res.status(err.response.status).json(
        {
            error: err.response.data?.error,
            error_description: err.response.data?.error_description,
            status: err.response.status,
            status_text: err.response.statusText,
        });
    }

    res.status(200).send();
});

app.post('/logout', (req, res)　=>
{
    console.log('logout');

    req.session.destroy();

    res.status(200).send();
})






//リッスンを開始します
const server = app.listen(3000, () =>
{
    console.log(`app listening at http://localhost:${server.address().port}`);
});
