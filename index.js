const express = require("express");
const app = require("./app");

app.listen(8080, () => {
  console.log("listining to 8080");
})

const USERS = []
const INFORMATION = []
const REFRESHTOKENS = []

const Admin = { email: "admin@email.com", name: "admin", password: "**hashed password**", isAdmin: true };

const Adminpass = "Rc123456!";