const util = require("util");

util.run("who am i|awk '{ print $5}'").then((stuff) => {
    console.log(stuff.stdout);
    console.log(stuff.stderr);
})