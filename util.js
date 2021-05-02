const exec = require("child_process").exec;
const evilscan = require("evilscan");

let run = function(command) {
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            let output = {}
            if (error) {
                reject(error);
            }
            if (stderr) {
                output.stderr = stderr;
            }
            output.stdout = stdout;
            resolve(output);
        })
    });
}

let grabIP = function(line) {
    let words = line.split(" ");
    for (let word of words) {
        if (word.includes(".") && word.split(".").length === 4) {
            return word;
        }
    }
    return "";
}

let portScan = function() {
    return new Promise((resolve, reject) => {
        let scan = new evilscan({
            target:"127.0.0.1",
            port:'0-65535',
            status:'O', // Timeout, Refused, Open, Unreachable
            banner:false
        });
        let data = [];
        scan.on = scan.on || function(){};
        scan.on('result', (stuff) => {
            data.push(stuff);
        });
        scan.on('error', (err) => {
            throw new Error(err);
        });
        scan.on("done", () => {
            resolve(data);
        });
        scan.run();
    });
}

let removeEmpty = function(arr) {
    let output = [];
    for (let item of arr) {
        if (item !== "") {
            output.push(item);
        }
    }
    return output;
}

let getUFWStatus = async function() {
    let result = await run("sudo ufw status");
    if (!result.stdout.includes("active")) {
        return {
            "status": "disabled"
        }
    }
    let ports = [];
    let ufw = result.stdout.split("\n");
    ufw = ufw.slice(4);
    ufw.pop();
    ufw.pop();
    for (let line of ufw) {
        let info = removeEmpty(line.split(" "));
        ports.push({
            port: info[0],
            status: info[1],
            from: info[2]
        });
    }
    return {
        "status": "enabled",
        "ports": ports
    };
}

module.exports.run = run;
module.exports.grabIP = grabIP;
module.exports.portScan = portScan;
module.exports.getUFWStatus = getUFWStatus;