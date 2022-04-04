const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
app.use(express.json());
const port = 6000;

const users = [
  {
    id: '1',
    username: 'chankyu',
    password: '12345',
    isAdmin: true,
  },
  {
    id: '2',
    username: 'minkyu',
    password: '123123',
    isAdmin: false,
  },
];

let refreshTokens = [];

app.post('/api/refresh', (req, res) => {
  //take the refresh token from the user
  const refreshToken = req.body.token;
  //send error if there is no token or it's invalid
  if (!refreshToken) return res.status(401).json('You are not Authenticated!');
  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json('Refresh token is not valid!');
  }
  jwt.verify(refreshToken, 'myRefreshSecretKey', (err, user) => {
    err && console.log(err);
    refreshTokens = refreshTokens.filter(token => token !== refreshToken); //해당 리프레쉬 토큰을 없애준다

    //새로운 accessToken과 RefreshToken을 만들어줌.
    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    //refreshTokens에 새로운 refreshToken을 넣어줌.
    refreshTokens.push(newRefreshToken);

    res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  });
  console.log('리프레쉬 시 refreshTokens', refreshTokens);
  // console.log('refresh 미들웨어 시 refreshTokens', refreshTokens);
  //if everything is ok, create new access token, refresh token and send to user
});

const generateAccessToken = user => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, 'mySecretKey', {
    expiresIn: '10s',
  });
};

const generateRefreshToken = user => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, 'myRefreshSecretKey');
};

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(user => {
    return user.username === username && user.password === password;
  });

  if (!user) {
    return res.status(400).json('username or password incorrect');
  }
  //Generate an access token
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);
  refreshTokens.push(refreshToken);

  res.json({
    id: user.id,
    username: user.username,
    isAdmin: user.isAdmin,
    accessToken,
    refreshToken,
  });

  console.log('로그인 시 refreshTokens', refreshTokens);
});

const verify = (req, res, next) => {
  const authHeader = req.headers.authorization;
  // console.log('authHeader', authHeader);
  if (!authHeader) {
    return res.status(401).json('you are not authenticated!');
  }

  const token = authHeader.split(' ')[1];
  // console.log('token', token);

  jwt.verify(token, 'mySecretKey', (err, user) => {
    if (err) {
      return res.status(401).json('Token is not valid!');
    }

    req.user = user;
    // console.log('req.user', req.user);
    next();
  });
};

app.post('/api/logout', verify, (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter(token => token !== refreshToken);
  res.status(200).json('You logged out successfully.');
  // console.log('로그아웃 시 refreshTokens', refreshTokens);
});

app.delete('/api/users/:userId', verify, (req, res) => {
  // console.log('req.user.id', req.user.id);
  // console.log('req.params.userId', req.params.userId);
  // console.log('req.user.isAdmin', req.user.isAdmin);

  if (req.user.id === req.params.userId || req.user.isAdmin) {
    return res.status(200).json('User has been deleted.');
  }
  res.status(403).json('You are not allowed to delete this user!');
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

//로그인한 accesstoken으로 delete의 authorization 을 맞추어줘야함.
