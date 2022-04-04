import { useState } from 'react';
import './App.css';
import axios from 'axios';
import jwt_decode from 'jwt-decode';

function App() {
  const [user, setUser] = useState(null);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(false);
  const [success, setSuccess] = useState(false);

  const refreshToken = async () => {
    try {
      const res = await axios.post('/api/refresh', { token: user.refreshToken });
      setUser({
        ...user,
        accessToken: res.data.accessToken,
        refreshToken: res.data.refreshToken,
      });
    } catch (error) {
      console.log(error);
    }
  };

  axios.create().interceptors.request.use(
    async config => {
      let currentDate = new Date();
      const decodedToken = jwt_decode(user.accessToken);
      if (decodedToken.exp * 1000 < currentDate.getTime()) {
        const data = await refreshToken();
        config.headers['authorization'] = 'Bearer ' + data.accessToken;
      }
      return config;
    },
    error => {
      return Promise.reject(error);
    }
  );

  // console.log(jwt_decode(user.accessToken));

  const handleSubmit = async e => {
    e.preventDefault();
    try {
      const res = await axios.post('/api/login', { username, password });
      setUser(res.data);
    } catch (error) {
      setError(error);
    }
  };

  const handleDelete = async id => {
    setSuccess(false);
    setError(false);
    try {
      await axios.create().delete('/api/users/' + id, {
        headers: { authorization: 'Bearer ' + user.accessToken },
      });
      setSuccess(true);
    } catch (err) {
      setError(true);
    }
  };

  return (
    <div className="container">
      {user ? (
        <div className="home">
          <span>
            Welcome to the <b>{user.isAdmin ? 'admin' : 'user'}</b> dashboard <b>{user.username}</b>
            .
          </span>
          <span>Delete Users:</span>
          <button className="deleteButton" onClick={() => handleDelete(1)}>
            Delete chankyu
          </button>
          <button className="deleteButton" onClick={() => handleDelete(2)}>
            Delete minkyu
          </button>
          {error && <span className="error">You are not allowed to delete this user!</span>}
          {success && <span className="success">User has been deleted successfully...</span>}
        </div>
      ) : (
        <div className="login">
          <form onSubmit={handleSubmit}>
            <span className="formTitle">Lama Login</span>
            <input type="text" placeholder="username" onChange={e => setUsername(e.target.value)} />
            <input
              type="password"
              placeholder="password"
              onChange={e => setPassword(e.target.value)}
            />
            <button type="submit" className="submitButton">
              Login
            </button>
          </form>
        </div>
      )}
    </div>
  );
}

export default App;
