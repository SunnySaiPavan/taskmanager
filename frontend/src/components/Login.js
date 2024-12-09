import React, { useState } from "react";
import axios from "axios";

const Login = ({ onLoginSuccess, onNavigateToRegister }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post("http://localhost:3000/login", {
        username,
        password,
      });
      localStorage.setItem("token", response.data.token); // Store JWT token
      onLoginSuccess(); // Navigate to dashboard
    } catch (error) {
      alert("Login Failed!");
    }
  };

  return (
    <div>
      <h2>Login</h2>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <button type="submit">Login</button>
      </form>
      <p>
        Don't have an account?{" "}
        <button onClick={onNavigateToRegister}>Register</button>
      </p>
    </div>
  );
};

export default Login;
