import React, { useState } from "react";
import axios from "axios";

const Register = ({ onNavigateToLogin }) => {
  const [formData, setFormData] = useState({
    username: "",
    name: "",
    password: "",
    gender: "Male",
    location: "",
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await axios.post("http://localhost:3000/users", formData);
      alert("Registration Successful!");
      onNavigateToLogin(); // Navigate to login after successful registration
    } catch (error) {
      alert("Registration Failed!");
    }
  };

  return (
    <div>
      <h2>Register</h2>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Username"
          value={formData.username}
          onChange={(e) => setFormData({ ...formData, username: e.target.value })}
        />
        <input
          type="text"
          placeholder="Name"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
        />
        <input
          type="password"
          placeholder="Password"
          value={formData.password}
          onChange={(e) => setFormData({ ...formData, password: e.target.value })}
        />
        <select
          value={formData.gender}
          onChange={(e) => setFormData({ ...formData, gender: e.target.value })}
        >
          <option value="Male">Male</option>
          <option value="Female">Female</option>
        </select>
        <input
          type="text"
          placeholder="Location"
          value={formData.location}
          onChange={(e) => setFormData({ ...formData, location: e.target.value })}
        />
        <button type="submit">Register</button>
      </form>
      <p>
        Already have an account?{" "}
        <button onClick={onNavigateToLogin}>Login</button>
      </p>
    </div>
  );
};

export default Register;
