const express = require("express");
const evilscan = require("evilscan");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 3000;

app.set('trust proxy', true);

let grabIP = function(line) {
    let words = line.split(":");
    for (let word of words) {
        if (word.includes(".") && word.split(".").length === 4) {
            return word;
        }
    }
    return "";
}

app.get('/scan/:ip', async(req, res) => {
    let ip = req.params.ip;
    if (!ip) {
        res.json({"status":"error"});
        return;
    }
    let scan = new evilscan({
        target:ip,
        port:'0-1000',
        status:'O', // Timeout, Refused, Open, Unreachable
        banner:false
    });
    console.log("scanning "+ip+"...")
    let data = [];
    scan.on = scan.on || function(){};

    scan.on('result', (stuff) => {
        data.push(stuff);
    });

    scan.on('error', (err) => {
        res.json({"status":"error"});
    });

    scan.on('done', () => {
        res.json({
            "status": "success",
            "data": data
        });
    });

    scan.run();
})

app.listen(port, () => {
    console.log(`App listening at http://localhost:${port}`)
})