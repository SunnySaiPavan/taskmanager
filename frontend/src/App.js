import React, { useState } from "react";
import Login from "./components/Login";
import Register from "./components/Register";
import Dashboard from "./components/Dashboard";

const App = () => {
  const [currentView, setCurrentView] = useState("login"); // Controls the active view
  const [isLoggedIn, setIsLoggedIn] = useState(false); // Tracks login status

  const handleLoginSuccess = () => {
    setIsLoggedIn(true);
    setCurrentView("dashboard");
  };

  const handleNavigateToRegister = () => {
    setCurrentView("register");
  };

  const handleNavigateToLogin = () => {
    setCurrentView("login");
  };

  return (
    <div>
      {currentView === "login" && (
        <Login 
          onLoginSuccess={handleLoginSuccess} 
          onNavigateToRegister={handleNavigateToRegister} 
        />
      )}
      {currentView === "register" && (
        <Register onNavigateToLogin={handleNavigateToLogin} />
      )}
      {isLoggedIn && currentView === "dashboard" && <Dashboard />}
    </div>
  );
};

export default App;
