const fs = require("fs");
const auth = require("./auth");

const data = fs.readFileSync('./auth.log', {encoding:'utf8', flag:'r'});

console.log(auth.analyzeAuthLog(data));