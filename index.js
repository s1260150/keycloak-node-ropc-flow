const express = require('express');
const session = require('express-session');
const axios = require('axios');
const qs = require('qs');
const jwt_decode = require('jwt-decode');
const KcAdminClient = require('keycloak-admin').default;
const { Issuer } = require('openid-client');


//管理アカウント用の Keycloak アダプター
const kcAdminClient = new KcAdminClient();


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



app.use(async (req, res, next) =>
{
    console.log(`request to "${req.url}"`);

    //アクセストークンが取得済みのユーザのみ通過させる
    if(req.url.indexOf("/login") > -1 || req.url.indexOf("/register") > -1 || req.session.access_token)
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

    try
    {
        //リソースオーナー・パスワード・クレデンシャルズフローを利用
        const body = 
        {
            grant_type: 'password',
            scope: 'openid profile',
            client_id: 'js-console',
            client_secret: 'eb261cff-5580-4b50-8806-980794d77f76',
            username: username,
            password: password,
        }
        const axiosConfig = { headers: { } };
    
        const response = await axios.post('http://localhost:8080/auth/realms/ROPC/protocol/openid-connect/token', qs.stringify(body), axiosConfig);


        req.session.access_token = response.data.access_token;
        req.session.refresh_token = response.data.refresh_token;
        req.session.id_token = response.data.id_token;
    
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
        await kcAdminClient.users.create(
        {
            realm: 'ROPC',
            username,
            enabled: true,
            firstName: firstname,
            lastName: lastname,
            credentials: [ { "type": "password", "value": password, "temporary": false } ]
        });

        res.status(200).send();
    }
    catch(err)
    {
        console.log(err);

        res.status(500).send();
    }
});

app.post('/logout', (req, res)　=>
{
    console.log('logout');

    req.session.destroy();

    res.status(200).send();
})






//リッスンを開始します
const server = app.listen(3000, async () =>
{
    console.log(`app listening at http://localhost:${server.address().port}`);
    
    //管理アカウントのトークンを取得
    await kcAdminClient.auth(
    {
        username: 'admin',
        password: 'admin',
        grantType: 'password',
        clientId: 'admin-cli',
    });


    // 以下、トークンをリフレッシュするための処理
    const keycloakIssuer = await Issuer.discover('http://localhost:8080/auth/realms/master');
      
    const client = new keycloakIssuer.Client(
    {
        client_id: 'admin-cli',
        token_endpoint_auth_method: 'none', // to send only client_id in the header
    });
    
    let tokenSet = await client.grant(
    {
        grant_type: 'password',
        username: 'admin',
        password: 'admin',
    });

    setInterval(async () =>
    {
        const refreshToken = tokenSet.refresh_token;

        tokenSet = await client.refresh(refreshToken);
        
        kcAdminClient.setAccessToken(tokenSet.access_token);

    }, 58 * 1000); // 58 seconds
});
